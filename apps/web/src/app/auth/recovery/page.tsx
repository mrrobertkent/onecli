import Image from "next/image";
import { RecoveryForm } from "./_components/recovery-form";

/**
 * Redeems a recovery key minted on the host with
 * `onecli-gateway create-recovery-key`.
 *
 * Unlisted: nothing links here, and the key in the query string is what is
 * being checked, not the URL. Rendering the form is deliberately unguarded —
 * the key is only ever verified in the server action, so a wrong or expired one
 * looks exactly like a right one until it is submitted.
 */

export default async function RecoveryPage({
  searchParams,
}: {
  searchParams: Promise<{ key?: string }>;
}) {
  const { key } = await searchParams;

  return (
    <div className="bg-background flex min-h-svh flex-col items-center justify-center px-6 pb-24">
      <div className="mb-8">
        <Image
          src="/onecli-full-logo.png"
          alt="onecli"
          width={140}
          height={40}
          priority
          className="dark:hidden"
        />
        <Image
          src="/onecli-full-logo-dark.png"
          alt="onecli"
          width={140}
          height={40}
          priority
          className="hidden dark:block"
        />
      </div>

      <div className="mb-8 text-center">
        <h1 className="font-[family-name:var(--font-serif)] text-4xl font-semibold tracking-tight sm:text-5xl">
          Emergency recovery
        </h1>
        <p className="text-muted-foreground mt-3 max-w-md text-base">
          Set a password for the account this key was minted for. You will be
          signed in with it, without the identity provider.
        </p>
      </div>

      <RecoveryForm recoveryKey={key ?? ""} />
    </div>
  );
}
