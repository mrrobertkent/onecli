export const getDashboardRedirect = (
  data: Record<string, unknown>,
  pathname: string,
): string | null => {
  // A credential the user did not choose — a bootstrap admin seeded from a
  // plaintext environment variable. It has been readable in container
  // configuration and process listings, so nothing else is reachable until it
  // is rotated. Checked before the project redirect: an admin with no project
  // yet must still land here, not on /create-org.
  if (
    data.mustChangePassword &&
    !pathname.startsWith("/auth/change-password")
  ) {
    return "/auth/change-password";
  }
  if (!data.projectId && !pathname.startsWith("/account")) {
    return "/create-org";
  }
  return null;
};
