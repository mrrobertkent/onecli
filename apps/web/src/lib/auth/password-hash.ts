import { hash, verify } from "@node-rs/argon2";

/**
 * Password hashing, isolated from the auth library so the KDF choice is
 * testable without booting the auth stack. Better Auth's default scrypt sits
 * below the OWASP minimum, hence the override.
 *
 * Output is PHC-format, so the parameters travel with the hash and can be
 * raised later without invalidating existing passwords.
 */

/** `Algorithm.Argon2id`, inlined: it is an ambient `const enum`, unreadable
 * under `isolatedModules`. */
const ARGON2ID = 2;

/** OWASP Password Storage Cheat Sheet, Argon2id minimum: m=19456 KiB, t=2, p=1. */
const ARGON2_OPTIONS = {
  algorithm: ARGON2ID,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
} as const;

export const hashPassword = async (password: string): Promise<string> =>
  hash(password.normalize("NFKC"), ARGON2_OPTIONS);

/**
 * Verify a password against a stored PHC hash. A malformed hash returns false
 * rather than throwing, so a corrupt row fails the login instead of surfacing
 * as a 500 that distinguishes it from a wrong password.
 */
export const verifyPassword = async (
  storedHash: string,
  password: string,
): Promise<boolean> => {
  try {
    return await verify(storedHash, password.normalize("NFKC"));
  } catch {
    return false;
  }
};
