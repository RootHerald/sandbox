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

## Run the client on Windows

`client/` is one C program that runs enrollment, attestation, signing and
decryption against the backend, built against the prebuilt SDK in `sdk/`.

In Visual Studio 2022 with the "Desktop development with C++" workload, not
running as administrator: File > Open > Folder on `client/`, then press F10 to
step through `main`.

Or, from `client/` in a Developer PowerShell for VS 2022:

```powershell
cmake --preset windows
cmake --build --preset windows
.\out\build\windows\Debug\sandbox-client.exe
```

The first run shows one UAC prompt. `RootHeraldEnrollComplete` needs an
elevated process, so the program relaunches itself for that call alone.

## Run the client on Linux

On Ubuntu 24.04 with a TPM at `/dev/tpmrm0`, install the build tools, add
yourself to the `tss` group that owns the TPM, and let that group read the
firmware event log:

```bash
sudo apt install build-essential cmake pkg-config libtss2-dev libssl-dev libcurl4-openssl-dev
sudo usermod -aG tss $USER
echo 'z /sys/kernel/security/tpm0/binary_bios_measurements 0440 root tss -' | sudo tee /etc/tmpfiles.d/rootherald-eventlog.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/rootherald-eventlog.conf
```

Log out and back in so the group applies, then from `client/`:

```bash
cmake --preset linux
cmake --build --preset linux
./out/build/linux/sandbox-client
```

On Windows or Linux, if you changed `SANDBOX_PORT`, set
`SANDBOX_URL=http://127.0.0.1:<port>` before running the client.

## Run the client in a container

The same program, built in a Linux container and run against swtpm, a software
TPM. It needs Docker and the key in `.env`, nothing else. From the repository
root:

```bash
docker compose up -d
docker compose run --rm client
```

The software TPM is kept in a Docker volume, so every run is the same device.
`docker compose --profile client down -v` deletes it, and the next run is a new
device with a new `ueid`.

## Build, run, see why, edit

1. Run the client.
2. Read the verdict on the backend's page, `http://localhost:47823/`: the
   outcome, the chip kind, whether the hardware is genuine, and the device's
   `ueid`.
3. Edit the policy in the dashboard, run again, and compare. The second run
   reuses `client/state/ak.blob`, so it skips enrollment and the page shows the
   same `ueid`. Delete `client/state/` to enroll again.

| The client prints | Meaning |
|---|---|
| `Software TPM: swtpm in this container` | The container's client runs against swtpm, not a hardware TPM |
| `RootHerald SDK: ABI 8.1, library <version>` | The SDK the client is linked against |
| `Backend:`, `State:` | Where it sends each step, and where it keeps the attestation key blob |
| `Platform:` | What `RootHeraldPreCheck` read on the device |
| `Enrollment skipped: state/ak.blob loads` | The device is enrolled from an earlier run |
| `  RootHerald<Verb>: <n> bytes` | An SDK call and the size of what it produced |
| `  POST <route>  <result>` | The backend's `result` for that step, as sent |
| `stopped at <route>` | The backend refused that step; nothing after it runs |

The client exits 0 when all four use cases complete, 2 when the backend stopped
the run, and 1 on a local failure.

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
