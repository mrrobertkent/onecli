"use client";

import { useEffect, useRef } from "react";

export interface AppConnectedEvent {
  provider?: string;
  /** Set only when the popup created a connection, so a listener can tell a
   * new account from refreshed credentials. */
  connectionId?: string;
}

interface UseAppMessagesOptions {
  onConnected: (event: AppConnectedEvent) => void;
  onConfigure?: (provider: string) => void;
}

/**
 * Listens for `postMessage` events from the app-connect popup and dispatches to
 * `onConnected` or `onConfigure`.
 *
 * Handlers are read through refs so the listener attaches once per lifetime
 * rather than re-subscribing on every render for inline callbacks.
 */
export const useAppMessages = ({
  onConnected,
  onConfigure,
}: UseAppMessagesOptions) => {
  const onConnectedRef = useRef(onConnected);
  useEffect(() => {
    onConnectedRef.current = onConnected;
  }, [onConnected]);
  const onConfigureRef = useRef(onConfigure);
  useEffect(() => {
    onConfigureRef.current = onConfigure;
  }, [onConfigure]);

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      if (event.data?.type === "app-connected") {
        onConnectedRef.current({
          provider: event.data.provider as string | undefined,
          connectionId: event.data.connectionId as string | undefined,
        });
      }
      if (event.data?.type === "app-configure" && event.data?.provider) {
        onConfigureRef.current?.(event.data.provider as string);
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);
};
