import { decodeBase64 } from "https://deno.land/std@0.204.0/encoding/base64.ts";
import type { Context, MiddlewareHandler } from "npm:hono@3.8.3";
import { HTTPException } from "npm:hono@3.8.3/http-exception";
import { verifySignature } from "npm:nostr-tools@1.17.0";

type NostrAuthOptions = {
  maxCreatedAtDiffSec?: number;
  checkPayloadHash?: boolean;
  additionalCheck?: (c: Context, authEvent: NostrEvent) => boolean;
};

export const nostrAuth = (
  options: NostrAuthOptions = {}
): MiddlewareHandler => {
  const { maxCreatedAtDiffSec, checkPayloadHash, additionalCheck } = {
    maxCreatedAtDiffSec: options.maxCreatedAtDiffSec ?? 30,
    checkPayloadHash: options.checkPayloadHash ?? false,
    additionalCheck: options.additionalCheck,
  };
  if (maxCreatedAtDiffSec < 0) {
    throw new Error("nostrAuth: maxEventAgeSec must be non-negative");
  }

  return async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader) {
      console.log("missing Authorization header");
      throw new HTTPException(401);
    }

    const [scheme, authPayload] = authHeader.split(" ");
    if (scheme !== "Nostr") {
      console.log("invalid auth scheme: should be 'Nostr'");
      throw new HTTPException(401);
    }
    if (!authPayload) {
      console.log("missing auth payload");
      throw new HTTPException(401);
    }

    const authEv = decodeNostrEvent(authPayload);
    if (authEv === undefined) {
      console.log("auth payload is not a valid Nostr event");
      throw new HTTPException(401);
    }

    // 1. The kind MUST be 27235.
    if (authEv.kind !== 27235) {
      console.log("invalid kind: should be 27235");
      throw new HTTPException(401);
    }

    // 2. The created_at timestamp MUST be within a reasonable time window.
    const currTime = currUnixtimeSec();
    if (Math.abs(currTime - authEv.created_at) > maxCreatedAtDiffSec) {
      console.log(
        "created_at is out of allowed range (current time: %d, created_at: %d)",
        currTime,
        authEv.created_at
      );
      throw new HTTPException(401);
    }

    // 3. The u tag MUST be exactly the same as the absolute request URL (including query parameters).
    const uTag = getTagValueByName(authEv, "u");
    if (uTag !== c.req.url) {
      console.log(
        "request URL doesn't match with value of u tag (req URL: %s, u tag: %s)",
        c.req.url,
        uTag
      );
      throw new HTTPException(401);
    }

    // 4. The method tag MUST be the same HTTP method used for the requested resource.
    const methodTag = getTagValueByName(authEv, "method");
    if (methodTag !== c.req.method) {
      console.log(
        "request method doesn't match with value of method tag (req method: %s, method tag: %s)",
        c.req.method,
        methodTag
      );
      throw new HTTPException(401);
    }

    if (checkPayloadHash) {
      // When the request contains a body (as in POST/PUT/PATCH methods) clients SHOULD
      // include a SHA256 hash of the request body in a payload tag as hex (["payload", "<sha256-hex>"]),
      // servers MAY check this to validate that the requested payload is authorized.
      const body = await c.req.arrayBuffer();
      if (body.byteLength > 0) {
        const payloadTag = getTagValueByName(authEv, "payload");
        if (!payloadTag) {
          console.log("checkPayloadHash is enabled but payload-tag is missing");
          throw new HTTPException(401);
        }
        const payloadHash = await crypto.subtle.digest("SHA-256", body);
        if (arrayBufferToHex(payloadHash) !== payloadTag) {
          console.log("value of payload-tag doesn't match payload hash");
          throw new HTTPException(401);
        }
      } else {
        console.log(
          "checkPayloadHash is enabled, but skipped since request body is empty"
        );
      }
    }

    // Servers MAY perform additional implementation-specific validation checks.
    if (additionalCheck !== undefined && !additionalCheck(c, authEv)) {
      console.log("custom additional check failed");
      throw new HTTPException(401);
    }

    await next();
  };
};

export type NostrEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

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
  } catch (err) {
    console.log("decodeNostrEvent:", err);
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
