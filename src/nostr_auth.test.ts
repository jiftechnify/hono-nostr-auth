import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { EventTemplate, finishEvent, generatePrivateKey } from "nostr-tools";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NostrEvent, nostrAuth, verifyPayloadHash } from "./nostr_auth";

const privkey = generatePrivateKey();

const validAuthEventTemplate = (
  reqUrl: string,
  method: string
): EventTemplate => {
  return {
    kind: 27235,
    tags: [
      ["u", reqUrl],
      ["method", method],
    ],
    content: "",
    created_at: 100,
  };
};

const encodeBase64 = (s: string): string => {
  const bytes = new TextEncoder().encode(s);
  const binString = String.fromCodePoint(...bytes);
  return btoa(binString);
};

const tokenifyEvent = (e: NostrEvent): string =>
  encodeBase64(JSON.stringify(e));

const setTag = (e: { tags: string[][] }, tagName: string, newValue: string) => {
  const newTags = [
    ...e.tags.filter(([n]) => n !== tagName),
    [tagName, newValue],
  ];
  e.tags = newTags;
};

describe("nostrAuth", () => {
  let handlerExecuted = false;

  vi.useFakeTimers();
  vi.setSystemTime(100 * 1e3);

  beforeEach(() => {
    handlerExecuted = false;
  });

  type Variables = {
    nostrAuthEvent: NostrEvent;
  };

  const app = new Hono<{ Variables: Variables }>();
  app.use("/auth", nostrAuth());

  app.get("/auth", (c) => {
    handlerExecuted = true;
    const authEv = c.get("nostrAuthEvent");
    return c.text(`hello, ${authEv.pubkey}!`);
  });

  it("should authorize a valid request", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = finishEvent(
      validAuthEventTemplate("http://localhost/auth", "GET"),
      privkey
    );
    req.headers.set("Authorization", `Nostr ${tokenifyEvent(authEv)}`);
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(200);
    expect(handlerExecuted).toBe(true);
    expect(await resp.text()).toBe(`hello, ${authEv.pubkey}!`);
  });

  it("should not authorize if 'Authorization' header is missing", async () => {
    const req = new Request("http://localhost/auth");
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
    expect(await resp.text()).toBe("'Authorization' header is missing");
  });

  it("should not authorize if auth scheme is not 'Nostr'", async () => {
    const req = new Request("http://localhost/auth");
    req.headers.set("Authorization", "Bearer 123");
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
    expect(await resp.text()).toBe("'Nostr' auth scheme is expected");
  });

  it("should not authorize if auth payload is missing", async () => {
    const req = new Request("http://localhost/auth");
    req.headers.set("Authorization", "Nostr");
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  it("should not authoriza if auth payload is not base64 encoded", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = finishEvent(
      validAuthEventTemplate("http://localhost/auth", "GET"),
      privkey
    );
    req.headers.set("Authorization", `Nostr ${JSON.stringify(authEv)}`); // omit base64 encoding
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  it("should not authorize if auth payload is not a valid nostr Event", async () => {
    const req = new Request("http://localhost/auth");
    const invalidEv = { hoge: "not a nostr event!" };
    req.headers.set(
      "Authorization",
      `Nostr ${encodeBase64(JSON.stringify(invalidEv))}`
    );
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  it("should not authorize if signature of auth event is invalid", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = finishEvent(
      validAuthEventTemplate("http://localhost/auth", "GET"),
      privkey
    );
    req.headers.set(
      "Authorization",
      `Nostr ${tokenifyEvent({ ...authEv, sig: "invalid" })}`
    ); // compromise the signature
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  it("should not authorize if kind of auth event is invalid", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = {
      ...validAuthEventTemplate("http://localhost/auth", "GET"),
      kind: 1, // invalid kind
    };
    req.headers.set(
      "Authorization",
      `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
    );
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  describe("timestamp diff treatment (default)", () => {
    beforeEach(() => {
      handlerExecuted = false;
    });

    it("should allow timestamp diff within threshold (past)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 - 30,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should allow timestamp diff within threshold (future)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 + 30,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should deny timestamp diff out of threshold (past)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 - 31,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });

    it("should deny timestamp diff out of threshold (future)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 + 31,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });
  });

  describe("timestamp diff treatment (with custom threshold)", () => {
    let handlerExecuted = false;
    beforeEach(() => {
      handlerExecuted = false;
    });

    const app = new Hono();
    app.use("/auth", nostrAuth({ maxCreatedAtDiffSec: 10 }));

    app.get("/auth", (c) => {
      handlerExecuted = true;
      return c.text("ok");
    });

    it("should allow timestamp diff within threshold (past)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 - 10,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should allow timestamp diff within threshold (future)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 + 10,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should deny timestamp diff out of threshold (past)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 - 11,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });

    it("should deny timestamp diff out of threshold (future)", async () => {
      const req = new Request("http://localhost/auth");
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth", "GET"),
        created_at: 100 + 11,
      };
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );
      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });
  });

  it("should not authorize if request URL doesn't match", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = validAuthEventTemplate("http://localhost/auth", "GET");
    setTag(authEv, "u", "http://localhost/invalid"); // set different URL
    req.headers.set(
      "Authorization",
      `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
    );
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  it("should not authorize if request method doesn't match", async () => {
    const req = new Request("http://localhost/auth");
    const authEv = validAuthEventTemplate("http://localhost/auth", "GET");
    setTag(authEv, "method", "POST"); // set different method
    req.headers.set(
      "Authorization",
      `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
    );
    const resp = await app.request(req);

    expect(resp).toBeDefined();
    expect(resp.status).toBe(401);
    expect(handlerExecuted).toBe(false);
  });

  describe("with additional check", () => {
    let handlerExecuted = false;
    beforeEach(() => {
      handlerExecuted = false;
    });

    const app = new Hono();
    app.use(
      "/auth/body",
      // pass only if request body matches with value of "body" tag
      nostrAuth({
        additionalCheck: async (c, authEv) => {
          const body = await c.req.text();
          const bodyTag =
            authEv.tags.find((tag) => tag[0] === "body")?.[1] ?? "";

          if (body !== bodyTag) {
            throw new HTTPException(401, { message: "body mismatch" });
          }
        },
      })
    );
    app.use(
      "/auth/payload-hash",
      nostrAuth({
        additionalCheck: verifyPayloadHash,
      })
    );

    app.post("/auth/*", (c) => {
      handlerExecuted = true;
      return c.text("ok");
    });

    it("should authorize if additional check passes (body)", async () => {
      const req = new Request("http://localhost/auth/body", {
        method: "POST",
        body: "Nostr",
      });
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth/body", "POST"),
      };
      setTag(authEv, "body", "Nostr");
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );

      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should not authorize if additional check fails (body)", async () => {
      const req = new Request("http://localhost/auth/body", {
        method: "POST",
        body: "Nostr",
      });
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth/body", "POST"),
      };
      setTag(authEv, "body", "invalid");
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );

      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
      expect(await resp.text()).toBe("body mismatch");
    });

    it("should authorize if additional check passes (payload-hash)", async () => {
      const req = new Request("http://localhost/auth/payload-hash", {
        method: "POST",
        body: "Nostr",
      });
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth/payload-hash", "POST"),
      };
      setTag(
        authEv,
        "payload",
        "cd27eb85bbbcde66be45dd832281190c0002b58be5c867e4f095d59b110c0c04"
      );
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );

      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(200);
      expect(handlerExecuted).toBe(true);
    });

    it("should not authorize if additional check fails (payload-hash)", async () => {
      const req = new Request("http://localhost/auth/payload-hash", {
        method: "POST",
        body: "Nostr",
      });
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth/payload-hash", "POST"),
      };
      setTag(
        authEv,
        "payload",
        "f1234d75178d892a133a410355a5a990cf75d2f33eba25d575943d4df632f3a4"
      );
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );

      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });

    it("should not authorize if additional check fails (payload-hash, tag missing)", async () => {
      const req = new Request("http://localhost/auth/payload-hash", {
        method: "POST",
        body: "Nostr",
      });
      const authEv = {
        ...validAuthEventTemplate("http://localhost/auth/payload-hash", "POST"),
      };
      // don't set payload tag
      req.headers.set(
        "Authorization",
        `Nostr ${tokenifyEvent(finishEvent(authEv, privkey))}`
      );

      const resp = await app.request(req);

      expect(resp).toBeDefined();
      expect(resp.status).toBe(401);
      expect(handlerExecuted).toBe(false);
    });
  });
});
