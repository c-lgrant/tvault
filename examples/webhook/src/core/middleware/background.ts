// Run work after the response is sent. On Workers that is `waitUntil` (keeps the
// isolate alive for the task); on Node there is no execution context, so the
// promise simply runs detached.

import type { Context } from "hono";
import type { BackgroundRunner } from "../protocol/oauthRefresh.ts";

export function backgroundRunner(c: Context): BackgroundRunner {
  return (task) => {
    try {
      c.executionCtx.waitUntil(task);
    } catch {
      // No ExecutionContext (Node, tests): leave it detached.
      void task.catch(() => undefined);
    }
  };
}
