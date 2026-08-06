import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
    },
  },
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    // The `*.pg.test.ts` suites drive one real database, and some of the state
    // they assert on is a singleton — `instance_settings` has exactly one row
    // no matter how many suites want to control it. Running files in parallel
    // makes those suites corrupt each other in ways that look like product
    // bugs. There are few enough files here that serialising costs nothing.
    fileParallelism: false,
  },
});
