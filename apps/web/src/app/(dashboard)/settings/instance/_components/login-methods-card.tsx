"use client";

import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Label } from "@onecli/ui/components/label";
import { Switch } from "@onecli/ui/components/switch";
import { setPasswordLogin } from "@/lib/actions/login-methods";
import type { LoginMethods } from "@/lib/actions/login-methods";

export interface LoginMethodsCardProps {
  methods: LoginMethods;
}

export const LoginMethodsCard = ({ methods }: LoginMethodsCardProps) => {
  const [enabled, setEnabled] = useState(methods.passwordLoginEnabled);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Turning it off is what the instance can refuse, so the switch is only
  // blocked in that direction — and only when there is nothing to fall back to.
  const wouldBeTheLastMethod = enabled && !methods.ssoConfigured;

  const onChange = async (next: boolean) => {
    setError(null);
    setSaving(true);
    setEnabled(next);

    const result = await setPasswordLogin(next);
    if (!result.ok) {
      setEnabled(!next);
      setError(result.error ?? "Something went wrong.");
    }
    setSaving(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Login methods</CardTitle>
        <CardDescription>
          How people sign in to this instance. At least one method stays enabled
          — the one that would leave no way in is refused.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between gap-4">
          <div className="space-y-1">
            <Label htmlFor="password-login">Email and password</Label>
            <p className="text-muted-foreground text-sm">
              {wouldBeTheLastMethod
                ? "The only way in until an identity provider is configured."
                : methods.lentByRecovery
                  ? "Off, but on right now for the length of the recovery window."
                  : "Sign in with a password held by this instance."}
            </p>
          </div>
          <Switch
            id="password-login"
            checked={enabled}
            disabled={saving || wouldBeTheLastMethod}
            onCheckedChange={onChange}
          />
        </div>

        <div className="flex items-center justify-between gap-4">
          <div className="space-y-1">
            <Label>Identity provider</Label>
            <p className="text-muted-foreground text-sm">
              {methods.ssoConfigured
                ? "Configured in the environment. Recovery never changes it."
                : "None configured."}
            </p>
          </div>
        </div>

        {error && (
          <p className="text-destructive text-sm" role="alert">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
};
