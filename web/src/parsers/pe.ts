// Minimal PE parser. Reads the optional header to find ImageBase,
// each IMAGE_SECTION_HEADER for region/readonly, and the export table
// for named functions. Doesn't process imports or relocations.

import type { ParsedBinary } from "@/decompiler/types";
import { archFromPe } from "@/decompiler/arch-map";
import { scanStrings } from "./index";

const IMAGE_SCN_MEM_WRITE = 0x80000000;

export async function parsePe(bytes: Uint8Array): Promise<ParsedBinary> {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint16(0, true) !== 0x5a4d)
    throw new Error("not a PE: missing MZ header");
  const peOff = dv.getUint32(0x3c, true);
  if (dv.getUint32(peOff, true) !== 0x4550)
    throw new Error("not a PE: missing PE\\0\\0 signature");

  const machine = dv.getUint16(peOff + 4, true);
  const numSections = dv.getUint16(peOff + 6, true);
  const optHeaderSize = dv.getUint16(peOff + 20, true);
  const optHeaderOff = peOff + 24;
  const optMagic = dv.getUint16(optHeaderOff, true);
  const isPe32Plus = optMagic === 0x20b;
  const archInfo = archFromPe(machine);

  // ImageBase lives at different offsets between PE32 and PE32+.
  const imageBase = isPe32Plus
    ? dv.getBigUint64(optHeaderOff + 24, true)
    : BigInt(dv.getUint32(optHeaderOff + 28, true));

  // Section headers immediately follow the optional header.
  const secOff = optHeaderOff + optHeaderSize;
  const regions: ParsedBinary["regions"] = [];
  const readonly: [bigint, bigint][] = [];
  type Section = { name: string; rva: bigint; vsize: number; raw: number; rawSize: number };
  const sections: Section[] = [];

  for (let i = 0; i < numSections; i++) {
    const off = secOff + i * 40;
    const name = readNul(bytes, off, 8);
    const vsize = dv.getUint32(off + 8, true);
    const vaddr = dv.getUint32(off + 12, true);
    const rawSize = dv.getUint32(off + 16, true);
    const rawPtr = dv.getUint32(off + 20, true);
    const chars = dv.getUint32(off + 36, true);

    const va = imageBase + BigInt(vaddr);
    sections.push({ name, rva: BigInt(vaddr), vsize, raw: rawPtr, rawSize });

    if (rawSize > 0) {
      regions.push({
        vaddr: va,
        bytes: bytes.subarray(rawPtr, rawPtr + rawSize),
      });
    }
    if ((chars & IMAGE_SCN_MEM_WRITE) === 0 && vsize > 0) {
      readonly.push([va, BigInt(vsize)]);
    }
  }

  // Export table → function symbols. RVA + size at data dir index 0.
  const dataDirOff = optHeaderOff + (isPe32Plus ? 112 : 96);
  const exportRva = dv.getUint32(dataDirOff, true);
  const symbols: [bigint, string][] = [];
  const functions: ParsedBinary["functions"] = [];
  if (exportRva > 0) {
    const exportFileOff = rvaToFile(exportRva, sections);
    if (exportFileOff != null) {
      const ordBase = dv.getUint32(exportFileOff + 16, true);
      const numFuncs = dv.getUint32(exportFileOff + 20, true);
      const numNames = dv.getUint32(exportFileOff + 24, true);
      const addrFuncsRva = dv.getUint32(exportFileOff + 28, true);
      const addrNamesRva = dv.getUint32(exportFileOff + 32, true);
      const addrOrdsRva = dv.getUint32(exportFileOff + 36, true);

      const funcsOff = rvaToFile(addrFuncsRva, sections);
      const namesOff = rvaToFile(addrNamesRva, sections);
      const ordsOff = rvaToFile(addrOrdsRva, sections);
      if (funcsOff != null && namesOff != null && ordsOff != null) {
        for (let i = 0; i < numNames; i++) {
          const nameRva = dv.getUint32(namesOff + i * 4, true);
          const ord = dv.getUint16(ordsOff + i * 2, true);
          if (ord >= numFuncs) continue;
          const fnRva = dv.getUint32(funcsOff + ord * 4, true);
          const nameFileOff = rvaToFile(nameRva, sections);
          if (nameFileOff == null) continue;
          let end = nameFileOff;
          while (end < bytes.length && bytes[end] !== 0) end++;
          const name = new TextDecoder().decode(bytes.subarray(nameFileOff, end));
          const addr = imageBase + BigInt(fnRva);
          symbols.push([addr, name]);
          functions.push({ addr, name });
          // ord+ordBase is reserved for ordinal lookups; we don't
          // surface those separately.
          void ordBase;
        }
      }
    }
  }

  // Strings from readonly regions.
  const strings: [bigint, number][] = [];
  for (const region of regions) {
    const isRO = readonly.some(([a]) => a === region.vaddr);
    if (!isRO) continue;
    strings.push(...scanStrings(region.vaddr, region.bytes));
  }

  const seen = new Set<string>();
  const uniqFunctions = functions
    .filter((f) => {
      const k = f.addr.toString();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort((a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0));

  // EntryPoint RVA at offset 16 of optional header.
  const epRva = dv.getUint32(optHeaderOff + 16, true);
  const entryPoint = epRva > 0 ? imageBase + BigInt(epRva) : undefined;

  return {
    format: "pe",
    arch: archInfo.arch,
    languageId: archInfo.languageId,
    regions,
    symbols,
    strings,
    readonly,
    entryPoint,
    functions: uniqFunctions,
  };
}

function rvaToFile(
  rva: number,
  secs: { rva: bigint; vsize: number; raw: number; rawSize: number }[],
): number | null {
  for (const s of secs) {
    const start = Number(s.rva);
    if (rva >= start && rva < start + s.vsize) {
      return s.raw + (rva - start);
    }
  }
  return null;
}

function readNul(bytes: Uint8Array, off: number, max: number): string {
  let end = off;
  const stop = Math.min(off + max, bytes.length);
  while (end < stop && bytes[end] !== 0) end++;
  return new TextDecoder().decode(bytes.subarray(off, end));
}
