// Ticket constraints (capability `ticketConstraints`). Both fields are optional;
// absent means pre-constraint behaviour.

import type { StoredDocument } from "../../runtime/context.ts";
import { alreadyExists, invalidRequest, staleCreation } from "./errors.ts";
import type { TicketPayload } from "./types.ts";

/** meta.creationId of a stored token (encrypted doc meta, or plaintext top-level). */
export function storedCreationId(doc: StoredDocument): unknown {
  const meta = (doc as Record<string, unknown>).meta;
  if (meta && typeof meta === "object" && "creationId" in meta) {
    return (meta as Record<string, unknown>).creationId;
  }
  return (doc as Record<string, unknown>).creationId;
}

/** Credential/proxy redemption: a ticket `cid` must match the stored creationId. */
export function assertCreationMatches(payload: TicketPayload, doc: StoredDocument): void {
  if (payload.cid === undefined) return;
  if (typeof payload.cid !== "string" || !payload.cid || storedCreationId(doc) !== payload.cid) {
    throw staleCreation("Token was replaced since this ticket was issued");
  }
}

/** Store redemption: validate mode/cid shapes and enforce create-only. */
export function assertStoreConstraints(payload: TicketPayload, existing: StoredDocument | null): void {
  if (payload.mode !== undefined && payload.mode !== "create" && payload.mode !== "overwrite") {
    throw invalidRequest("Invalid ticket mode");
  }
  if (payload.cid !== undefined && (typeof payload.cid !== "string" || !payload.cid)) {
    throw invalidRequest("Invalid ticket cid");
  }
  if (payload.mode === "create" && existing) {
    throw alreadyExists("A token already exists for this service");
  }
}
