/**
 * Policy runtime edition helpers. Pure and dependency-free (reads only
 * `process.env` plus the pure edition parser), so it is safe to import from
 * routes, middleware, or a standalone startup entry.
 */
import { parseEdition } from "./edition";

const runtimeEdition = () =>
  parseEdition(process.env.EDITION ?? process.env.NEXT_PUBLIC_EDITION).edition;

/** Whether this runtime is the OSS edition. The shared policy service uses it
 * to phrase capability rejections as OneCLI Cloud pointers. */
export const isOssEdition = (): boolean => runtimeEdition() === "oss";
