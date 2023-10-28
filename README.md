# hono-nostr-auth
[Nostr HTTP auth (NIP-98)](https://github.com/nostr-protocol/nips/blob/master/98.md) middleware for [Hono](https://hono.dev/)🔥.


## Usage

```
npm install hono-nostr-auth
```

```ts
import { Hono } from "hono";
import { nostrAuth, type NostrEvent } from "hono-nostr-auth";

// This is needed to type Context correctly in TypeScript
type Variables = {
    nostrAuthEvent: NostrEvent;
}

const app = new Hono<{ Variables: Variables }>();

app.use("/nostr-auth/*", nostrAuth());
app.get("/nostr-auth/hello", (c) => {
    // you can get the Nostr auth event from the context!
    const authEv = c.get("nostrAuthEvent");
    return c.text(`Hello, ${authEv.pubkey}!`);
});
```

### For Deno Users

```ts
import { Hono } from "npm:hono@3.9.0";
import { nostrAuth, type NostrEvent } from "npm:hono-nostr-auth@0.1.1";

type Variables = {
    nostrAuthEvent: NostrEvent;
}

const app = new Hono<{ Variables: Variables }>();

app.use("/nostr-auth/*", nostrAuth());
app.get("/nostr-auth/hello", (c) => {
    const authEv = c.get("nostrAuthEvent");
    return c.text(`Hello, ${authEv.pubkey}!`);
});

Deno.serve(app.fetch);
```


## Options
### `maxCreatedAtDiffSec?: number`
Default: `30`

It specifies maximum allowed difference between the server time and the request time (i.e. the auth event's `created_at`) in seconds.

For example, if you set it as `60`, requests with auth events that have `created_at` between 60 seconds before the server time and 60 seconds after the server time are considered valid.

### `additionalCheck?: NostrAuthAdditionalCheck`
Where:

```ts
type NostrAuthAdditinalCheck = 
    (c: Context, authEvent: NostrEvent) => void | Promise<void>;
```

Default: `undefined`

If specified, the middleware executes it as an additional request validation after basic checks (i.e. event signature verification, kind / created_at / URL / method validations).

Throwing an exception from within the check function rejects the request in question.
You can customize error responses by throwing an instance of [Hono's `HTTPException`](https://hono.dev/api/exception).

You can use this mechanism to implement the payload hash verification described in [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md).
`verifyPayloadHash` is the out-of-the-box implementation for it.

```ts
import { Hono } from 'hono';
import { nostrAuth, verifyPayloadHash } from 'hono-nostr-auth';

const app = new Hono();

app.use("*", nostrAuth({ additionalCheck: verifyPayloadHash }));
...
```

## Author
jiftechnify (https://github.com/jiftechnify)

## License
MIT
