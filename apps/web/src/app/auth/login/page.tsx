import { LoginContent } from "./_components/login-content";
import { isOAuthConfigured } from "@/lib/auth/auth-mode";
import { readLoginPolicy } from "@/lib/auth/login-policy";

export default async function LoginPage() {
  const { passwordLoginAvailable } = await readLoginPolicy();

  return (
    <LoginContent
      passwordLogin={passwordLoginAvailable}
      ssoConfigured={isOAuthConfigured()}
    />
  );
}
