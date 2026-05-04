// Monarch tokenizer + theme for Ghidra's decompiled C output. Built
// to highlight the synthetic identifiers Ghidra emits (FUN_*, DAT_*,
// LAB_*, iVar1, uVar2, ...) on top of normal C syntax. Standard C
// keywords get the usual treatment.

import type * as monacoNs from "monaco-editor";

export function registerPyreC(monaco: typeof monacoNs) {
  const id = "pyre-c";

  monaco.languages.register({ id, extensions: [".c"] });

  monaco.languages.setLanguageConfiguration(id, {
    comments: { lineComment: "//", blockComment: ["/*", "*/"] },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"', notIn: ["string"] },
      { open: "'", close: "'", notIn: ["string"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
    folding: { markers: { start: /^\s*\{/, end: /^\s*\}/ } },
  });

  monaco.languages.setMonarchTokensProvider(id, {
    defaultToken: "",
    keywords: [
      "auto", "break", "case", "char", "const", "continue", "default", "do",
      "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
      "long", "register", "return", "short", "signed", "sizeof", "static",
      "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
      "while", "_Bool", "_Complex", "_Imaginary",
      // Ghidra's printer emits these custom integer types.
      "uint", "uchar", "ushort", "ulong", "ulonglong", "longlong", "byte",
      "word", "dword", "qword", "code", "wchar_t", "wchar",
      "uint8_t", "uint16_t", "uint32_t", "uint64_t",
      "int8_t", "int16_t", "int32_t", "int64_t",
      "bool", "true", "false", "NULL",
    ],
    operators: [
      "=", ">", "<", "!", "~", "?", ":", "==", "<=", ">=", "!=",
      "&&", "||", "++", "--", "+", "-", "*", "/", "&", "|", "^",
      "%", "<<", ">>", "&=", "|=", "^=", "%=", "<<=", ">>=",
      "+=", "-=", "*=", "/=",
    ],
    symbols: /[=><!~?:&|+\-*/^%]+/,
    tokenizer: {
      root: [
        // Ghidra synthetic identifiers — give them their own colors so
        // the eye can spot them at a glance.
        [/\bFUN_[0-9a-fA-F]+\b/, "ghidra.func"],
        [/\bDAT_[0-9a-fA-F]+\b/, "ghidra.data"],
        [/\bLAB_[0-9a-fA-F]+\b/, "ghidra.label"],
        [/\bs_[0-9a-fA-F]+\b/, "ghidra.string"],
        [/\b(?:i|u|p|b|s|c|w|d|l)Var\d+\b/, "ghidra.var"],
        [/\b(?:in_)?[A-Za-z]+(?:RAX|RBX|RCX|RDX|RSI|RDI|RBP|RSP|R\d+)\b/, "ghidra.reg"],

        // Identifiers / keywords
        [
          /[a-zA-Z_]\w*/,
          {
            cases: {
              "@keywords": "keyword",
              "@default": "identifier",
            },
          },
        ],

        // Numbers
        [/0x[0-9a-fA-F]+[uUlL]*/, "number.hex"],
        [/\d+[uUlL]*/, "number"],

        // Strings + chars
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/"/, { token: "string.quote", bracket: "@open", next: "@string" }],
        [/'(\\.|.)'/, "string"],

        // Comments
        [/\/\/.*$/, "comment"],
        [/\/\*/, { token: "comment.quote", bracket: "@open", next: "@comment" }],

        // Punctuation + operators
        [/[{}()[\]]/, "@brackets"],
        [/[<>](?!@symbols)/, "@brackets"],
        [
          /@symbols/,
          {
            cases: {
              "@operators": "operator",
              "@default": "",
            },
          },
        ],
        [/[;,.]/, "delimiter"],
        [/\s+/, "white"],
      ],
      string: [
        [/[^\\"]+/, "string"],
        [/\\./, "string.escape"],
        [/"/, { token: "string.quote", bracket: "@close", next: "@pop" }],
      ],
      comment: [
        [/[^/*]+/, "comment"],
        [/\*\//, { token: "comment.quote", bracket: "@close", next: "@pop" }],
        [/[/*]/, "comment"],
      ],
    },
  });

  monaco.editor.defineTheme("pyre-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "comment", foreground: "5b6580", fontStyle: "italic" },
      { token: "keyword", foreground: "c084fc", fontStyle: "bold" },
      { token: "identifier", foreground: "e2e8f0" },
      { token: "number", foreground: "60a5fa" },
      { token: "number.hex", foreground: "60a5fa" },
      { token: "string", foreground: "86efac" },
      { token: "string.escape", foreground: "fbbf24" },
      { token: "operator", foreground: "f472b6" },
      // Ghidra-specific token types
      { token: "ghidra.func", foreground: "fde047", fontStyle: "bold" },
      { token: "ghidra.data", foreground: "fb923c" },
      { token: "ghidra.label", foreground: "94a3b8" },
      { token: "ghidra.string", foreground: "86efac" },
      { token: "ghidra.var", foreground: "67e8f9" },
      { token: "ghidra.reg", foreground: "f87171", fontStyle: "italic" },
    ],
    colors: {
      "editor.background": "#020617",
      "editor.foreground": "#e2e8f0",
      "editor.lineHighlightBackground": "#0f172a",
      "editor.selectionBackground": "#7c3aed40",
      "editorLineNumber.foreground": "#334155",
      "editorLineNumber.activeForeground": "#a78bfa",
      "editorIndentGuide.background": "#1e293b",
      "editorIndentGuide.activeBackground": "#334155",
    },
  });
}
