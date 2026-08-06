/**
 * The database gate for the `*.pg.test.ts` proof suites: skip locally when no
 * database is configured, throw in CI so the coverage cannot silently vanish
 * behind a renamed environment variable.
 */
export const proofDatabaseUrl = (): string | undefined => {
  const url = process.env.POLICY_PROOF_DATABASE_URL;
  if (url !== undefined && url !== "") return url;

  if (process.env.CI !== undefined && process.env.CI !== "") {
    throw new Error(
      "POLICY_PROOF_DATABASE_URL must be set in CI: the pg proof suites must " +
        "not silently skip. Start a PostgreSQL, run `prisma migrate deploy` " +
        "against it, and pass its URL to the test step.",
    );
  }

  return undefined;
};
