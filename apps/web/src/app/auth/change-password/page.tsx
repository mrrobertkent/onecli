import Image from "next/image";
import { ChangePasswordForm } from "@/app/auth/change-password/_components/change-password-form";

/**
 * Password rotation. Reached by the dashboard's redirect when a credential was
 * handed to the user rather than chosen by them, and usable on demand otherwise.
 */
export default function ChangePasswordPage() {
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

      <div className="bg-card w-full max-w-md rounded-2xl border p-8">
        <h1 className="text-base font-medium">Choose a new password</h1>
        <p className="text-muted-foreground mt-2 text-sm leading-relaxed">
          Your current password was set from the instance configuration, where
          it is readable by anyone who can inspect the container. Replace it
          before continuing.
        </p>
        <ChangePasswordForm />
      </div>
    </div>
  );
}
