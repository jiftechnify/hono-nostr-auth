import { decodeBase64 } from "https://deno.land/std@0.204.0/encoding/base64.ts";
import type { Context, MiddlewareHandler } from "npm:hono@3.8.3";
import { HTTPException } from "npm:hono@3.8.3/http-exception";
import { verifySignature } from "npm:nostr-tools@1.17.0";

export type NostrEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

/**
 * Type of functions that perform additional validations after basic checks.
 *
 * Throwing an exception from within the function rejects the request in question.
 * You can customize error responses by throwing an instance of Hono's `HTTPException`.
 */
export type NostrAuthAdditionalCheck = (
  c: Context,
  authEvent: NostrEvent
) => void | Promise<void>;

type NostrAuthOptions = {
  /**
   * Maximum allowed difference between the server time and the auth event's `created_at`.
   *
   * default: `30`
   */
  maxCreatedAtDiffSec?: number;

  /**
   * A function that performs additional request validations after basic checks.
   *
   * Throwing an exception from within this function rejects the request in question.
   * You can customize error responses by throwing an instance of Hono's `HTTPException`.
   *
   * default: `undefined`
   */
  additionalCheck?: NostrAuthAdditionalCheck;
};


/**
 * Nostr HTTP auth (NIP-98) middleware.
 * 
 * @example
 * ```js
 * import { Hono } from 'hono';
 * import { nostrAuth } from 'hono-nostr-auth';
 * 
 * const app = new Hono();
 * 
 * app.use("/nostr-auth/*", nostrAuth());
 * ...
 * ```
 */
export const nostrAuth = (
  options: NostrAuthOptions = {}
): MiddlewareHandler<{Variables: { nostrAuthEvent: NostrEvent }}> => {
  const { maxCreatedAtDiffSec, additionalCheck } = {
    maxCreatedAtDiffSec: options.maxCreatedAtDiffSec ?? 30,
    additionalCheck: options.additionalCheck,
  };
  if (maxCreatedAtDiffSec < 0) {
    throw new Error("nostrAuth: maxEventAgeSec must be non-negative");
  }

  return async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader) {
      throw new HTTPException(401, {
        message: "'Authorization' header is missing",
      });
    }

    const [scheme, authPayload] = authHeader.split(" ");
    if (scheme !== "Nostr") {
      throw new HTTPException(401, {
        message: "'Nostr' auth scheme is expected",
      });
    }
    if (!authPayload) {
      throw errInvalidAuthPayload;
    }

    const authEv = decodeNostrEvent(authPayload);
    if (authEv === undefined) {
      throw errInvalidAuthPayload;
    }

    // 1. The kind MUST be 27235.
    if (authEv.kind !== 27235) {
      throw errInvalidAuthPayload;
    }

    // 2. The created_at timestamp MUST be within a reasonable time window.
    const currTime = currUnixtimeSec();
    if (Math.abs(currTime - authEv.created_at) > maxCreatedAtDiffSec) {
      throw errInvalidAuthPayload;
    }

    // 3. The u tag MUST be exactly the same as the absolute request URL (including query parameters).
    const uTag = getTagValueByName(authEv, "u");
    if (uTag !== c.req.url) {
      throw errInvalidAuthPayload;
    }

    // 4. The method tag MUST be the same HTTP method used for the requested resource.
    const methodTag = getTagValueByName(authEv, "method");
    if (methodTag !== c.req.method) {
      throw errInvalidAuthPayload;
    }

    // Servers MAY perform additional implementation-specific validation checks.
    if (additionalCheck !== undefined) {
      try {
        await additionalCheck(c, authEv);
      } catch (err) {
        if (err instanceof HTTPException) {
          throw err;
        }

        if (err instanceof Error) {
          console.error(err);
        }
        throw errInvalidAuthPayload;
      }
    }

    c.set('nostrAuthEvent', authEv)

    await next();
  };
};

export const verifyPayloadHash = async (
  c: Context,
  authEvent: NostrEvent
): Promise<void> => {
  // When the request contains a body (as in POST/PUT/PATCH methods) clients SHOULD
  // include a SHA256 hash of the request body in a payload tag as hex (["payload", "<sha256-hex>"]),
  // servers MAY check this to validate that the requested payload is authorized.
  const body = await c.req.arrayBuffer();
  if (body.byteLength === 0) {
    return;
  }

  const payloadTag = getTagValueByName(authEvent, "payload");
  if (!payloadTag) {
    throw errInvalidAuthPayload;
  }
  const payloadHash = await crypto.subtle.digest("SHA-256", body);
  if (arrayBufferToHex(payloadHash) !== payloadTag.toLowerCase()) {
    throw errInvalidAuthPayload;
  }
};

const errInvalidAuthPayload = new HTTPException(401, {
  message: "invalid auth payload",
});

const txtDec = new TextDecoder("utf8");

const is32BytesHexStr = (s: string): boolean => {
  return /^[a-f0-9]{64}$/.test(s);
};
const is64BytesHexStr = (s: string): boolean => {
  return /^[a-f0-9]{128}$/.test(s);
};

const isNostrEvent = (v: unknown): v is NostrEvent => {
  if (typeof v !== "object" || v === null) {
    return false;
  }

  // id: 32-bytes lowercase hex-encoded sha256
  if (
    !("id" in v) ||
    typeof v["id"] !== "string" ||
    !is32BytesHexStr(v["id"])
  ) {
    return false;
  }

  // pubkey: 32-bytes lowercase hex-encoded public key
  if (
    !("pubkey" in v) ||
    typeof v["pubkey"] !== "string" ||
    !is32BytesHexStr(v["pubkey"])
  ) {
    return false;
  }

  // created_at: unix timestamp in seconds
  if (!("created_at" in v) || typeof v["created_at"] !== "number") {
    return false;
  }

  // kind: integer
  if (!("kind" in v) || typeof v["kind"] !== "number") {
    return false;
  }

  // tags: array of arrays of non-null strings
  if (!("tags" in v) || !Array.isArray(v["tags"])) {
    return false;
  }
  if (
    v["tags"].some(
      (tag) => !Array.isArray(tag) || tag.some((e) => typeof e !== "string")
    )
  ) {
    return false;
  }

  // content: string
  if (!("content" in v) || typeof v["content"] !== "string") {
    return false;
  }

  // sig: 64-bytes hex of the signature
  if (
    !("sig" in v) ||
    typeof v["sig"] !== "string" ||
    !is64BytesHexStr(v["sig"])
  ) {
    return false;
  }

  return true;
};

// decode base64-encoded event and verify signature
const decodeNostrEvent = (authPayload: string): NostrEvent | undefined => {
  try {
    const txt = txtDec.decode(decodeBase64(authPayload));
    const ev = JSON.parse(txt) as unknown;
    if (!isNostrEvent(ev) || !verifySignature(ev)) {
      return undefined;
    }
    return ev;
  } catch {
    return undefined;
  }
};

const currUnixtimeSec = () => Date.now() / 1000;

const getTagValueByName = (
  ev: NostrEvent,
  name: string
): string | undefined => {
  return ev.tags.find((tag) => tag[0] === name)?.[1];
};

const hexTable = (() => {
  const t = [];
  for (let n = 0; n < 0xff; n++) {
    t.push(n.toString(16).padStart(2, "0"));
  }
  return t;
})();

const arrayBufferToHex = (buffer: ArrayBuffer): string => {
  const bin = new Uint8Array(buffer);
  const res = [];
  for (let i = 0; i < bin.length; i++) {
    res.push(hexTable[bin[i]]);
  }
  return res.join("");
};
