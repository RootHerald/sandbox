# RootHerald sandbox

A local backend that holds your RootHerald secret key and calls RootHerald with
[`@rootherald/node`](https://www.npmjs.com/package/@rootherald/node). The device
talks only to this backend; the key never reaches it.

## Run the backend

1. In the [dashboard](https://rootherald.io/dashboard), build a policy in the
   policy builder and create an API key bound to it.
2. Put the key in `.env` and start the backend:

   ```bash
   cp .env.example .env    # then set ROOTHERALD_SECRET_KEY=rh_sk_...
   docker compose up
   ```

3. Open `http://localhost:47823/`. Each call appears there as it arrives, with
   what went to RootHerald and what came back.

`docker compose down -v` removes the sandbox's containers and network.

| Setting | Default |
|---|---|
| `ROOTHERALD_SECRET_KEY` | none; required |
| `SANDBOX_PORT` | `47823` |
| `ROOTHERALD_URL` | `https://rootherald.io` |

## Routes

The client calls these in order. Every request and response body is a JSON
object; every response field is a string, and every response carries `result`,
a line the client prints as-is. A 2xx means carry on; anything else ends the run.

| Route | Request | Backend calls | 2xx fields besides `result` | Non-2xx |
|---|---|---|---|---|
| `POST /enroll/begin` | EnrollBegin JSON | `relayEnroll` | `enrollChallenge`: the challenge as a JSON string | refusal |
| `POST /enroll/complete` | EnrollComplete JSON | `relayActivate` | none | refusal |
| `POST /attest/challenge` | `{}` | `issueChallenge` | `challenge` | refusal |
| `POST /attest/verify` | evidence JSON | `verify` | none | 403 `blocked — …`; 409 `not enrolled`; refusal |
| `POST /sign/challenge` | `{}` | `issueKeyChallenge`, purpose `sign` | `keyChallenge` | 409 `attest first`; refusal |
| `POST /sign/certify` | MintKey certification JSON | `certifyKey` | `message`: sign its UTF-8 bytes | refusal |
| `POST /sign/verify` | `{"signature":"<base64url>"}` | `verifyKeySignature` | none | 422 `signature does not verify`; 409 `attest first` |
| `POST /decrypt/challenge` | `{}` | `issueKeyChallenge`, purpose `decrypt` | `keyChallenge` | 409 `attest first`; refusal |
| `POST /decrypt/certify` | MintKey certification JSON | `certifyKey`, `encryptToDevice` | `jwe` | 422 `cannot encrypt to this key: <code>`; refusal |
| `POST /decrypt/verify` | `{"plaintext":"<base64url>"}` | none | none | 422 `wrong secret`; 409 `attest first` |

The verify `result` is `pass`, `warn` or `blocked`, then the chip kind, then
`, not genuine hardware` and `, no maker vouches for this chip` where they
apply. The certify `result` adds `, not hardware-bound` where it applies. The
device's `ueid` is in no response; the backend's console and its page show it.

A refusal keeps RootHerald's status and carries `error` and `message` as
RootHerald sent them, with device IDs replaced by `[device id]`. Its `result` is
`RootHerald refused: <error>`; that prefix is part of the contract. With no key
set, every route that calls RootHerald answers 401 `RootHerald refused:
MISSING_SECRET_KEY`.

The backend answers only requests whose `Host` is `localhost:<port>` or
`127.0.0.1:<port>`, and refuses cross-origin requests.

## Troubleshooting

If Docker says the port is already allocated, set `SANDBOX_PORT` in `.env` to a free port.
