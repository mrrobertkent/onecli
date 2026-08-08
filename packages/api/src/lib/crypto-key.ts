/**
 * The one rule for `SECRET_ENCRYPTION_KEY`, shared by the boot gate and the
 * crypto. Dependency-free because the web's middleware imports it.
 */

export const ENCRYPTION_KEY_BYTES = 32;

export type EncryptionKeyStatus = "ok" | "missing" | "malformed";

/** Said the same way wherever the key is refused. */
export const ENCRYPTION_KEY_HINT = `node -e "console.log(require('crypto').randomBytes(${ENCRYPTION_KEY_BYTES}).toString('base64'))"`;

/** Whether the value is a usable key, without decoding it into one. */
export const encryptionKeyStatus = (value: string): EncryptionKeyStatus => {
  if (!value) return "missing";
  try {
    return atob(value).length === ENCRYPTION_KEY_BYTES ? "ok" : "malformed";
  } catch {
    // Not base64 at all — a hex key pasted by mistake lands here.
    return "malformed";
  }
};
