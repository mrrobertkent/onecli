/**
 * The one rule for `SECRET_ENCRYPTION_KEY`, shared by the boot gate that
 * reports on it and the crypto that depends on it.
 *
 * Pure and dependency-free on purpose: the web's middleware imports it, and
 * anything reaching for `node:crypto` or `Buffer` there pulls Node into a bundle
 * that may not have it.
 */

export const ENCRYPTION_KEY_BYTES = 32;

export type EncryptionKeyStatus = "ok" | "missing" | "malformed";

/** Said the same way wherever the key is refused. */
export const ENCRYPTION_KEY_HINT = `node -e "console.log(require('crypto').randomBytes(${ENCRYPTION_KEY_BYTES}).toString('base64'))"`;

/**
 * Whether the value is a usable key, without decoding it into one.
 *
 * A wrong-length key is the interesting case: it is not missing, so a check for
 * emptiness passes it through, and it then fails at the first secret anyone
 * tries to store — long after the boot where it could have been reported.
 */
export const encryptionKeyStatus = (value: string): EncryptionKeyStatus => {
  if (!value) return "missing";
  try {
    return atob(value).length === ENCRYPTION_KEY_BYTES ? "ok" : "malformed";
  } catch {
    // Not base64 at all — a hex key pasted by mistake lands here.
    return "malformed";
  }
};
