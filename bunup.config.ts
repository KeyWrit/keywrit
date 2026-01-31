import { defineConfig } from "bunup";

export default defineConfig({
    entry: ["src/index.ts"],
    format: ["esm", "cjs", "iife"],
    dts: true,
    clean: true,
    minify: true,
    sourcemap: "external",
    globalName: "KeyWrit",
});
