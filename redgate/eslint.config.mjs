export default [
  {
    files: ["gateway/static/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: Object.fromEntries([
        "window", "document", "sessionStorage", "fetch", "URL", "URLSearchParams",
        "Blob", "setTimeout", "clearTimeout", "setInterval", "clearInterval",
        "FormData", "console", "module",
      ].map((key) => [key, "readonly"])),
    },
    rules: { "no-undef": "error", "no-unreachable": "error", "no-eval": "error", "no-implied-eval": "error" },
  },
  {
    files: ["tests/*.cjs"],
    languageOptions: {
      ecmaVersion: 2022, sourceType: "commonjs",
      globals: Object.fromEntries(["process", "__dirname", "setImmediate", "setTimeout", "clearTimeout", "URL", "URLSearchParams", "Blob", "Buffer", "console"].map((key) => [key, "readonly"])),
    },
    rules: { "no-undef": "error", "no-unreachable": "error" },
  },
];
