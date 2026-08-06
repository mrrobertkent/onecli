import { hash, verify } from "@node-rs/argon2";

/**
 * Password hashing, isolated from the auth library.
 *
 * This module deliberately imports NOTHING from `better-auth`. Authentication
 * is the library's job; the choice of KDF and its parameters is ours, and it
 * has to be testable without booting the auth stack.
 *
 * WHY WE OVERRIDE THE DEFAULT: Better Auth ships scrypt at `N=2^14, r=16, p=1`
 * (~32 MiB), which is BELOW the OWASP minimum. Argon2id at the parameters below
 * is OWASP's first recommendation and, at ~19 MiB, is also lighter than
 * OWASP-parameter scrypt (`N=2^17, r=8, p=1`, ~134 MiB per hash) — which
 * matters in a container where Node runs these on a 4-thread libuv pool.
 *
 * The output is PHC-format (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`), so the
 * parameters travel with the hash and can be raised later without invalidating
 * existing passwords.
 */

/**
 * `Algorithm.Argon2id` from `@node-rs/argon2` is an ambient `const enum`, which
 * cannot be read under `isolatedModules`. The value is inlined rather than left
 * to the library's default — an implicit default is not something a password
 * KDF should depend on.
 */
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
 * Verify a password against a stored PHC hash.
 *
 * Returns false rather than throwing on a malformed or unparseable hash: a
 * corrupt row must fail the login, not surface as a 500 that distinguishes it
 * from a wrong password.
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
