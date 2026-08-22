# Removable-media golden fixtures

This directory freezes small, deterministic input contracts for scanner,
admission, provenance, recovery, and hash/path tests. The fixtures do not
contain production recordings or personally identifying data.

## What is in the fixture set

`index.json` is the exhaustive case index and `provenance.json` is the
one-to-one provenance manifest for every indexed case. The grouped case files
cover:

- `SignedPublicationV1`, both with an explicitly injected test trust anchor
  and without one;
- complete but unpublished appliance v6 output;
- committed appliance v6 spool with a closed short tail, plus missing,
  duplicate, unclosed, commit-conflicting, and interrupted variants;
- standalone `ylx.stereo_imu.raw.v2` file transport at 30 and 60 fps, plus a
  failed capture, a bad JPEG byte range, a capture-sequence gap, and an IMU
  timestamp error;
- legacy appliance v5 MJPEG/fMP4 with the historical `video_mono` role,
  side-by-side geometry, per-segment PTS reset, a short final segment, and a
  continuous timeline reconstructed from `raw/frames.jsonl`;
- unsupported v1-v4 legacy input, malformed input, unknown major schema,
  interrupted input, same-size hash mismatch, path traversal, symlink, and
  reparse-point rejection.

The fixture documents use snake_case because they model RP-side artifacts.
Expected PC outcomes use the exact classifier and preflight names from the
design and research decision matrix.

## Lightweight virtual filesystem

Large or identifying video samples do not belong in this repository. Each
case therefore describes a virtual card tree:

- `json` entries hold a structured JSON document;
- `utf8` entries hold exact UTF-8 bytes, including explicit `\n` characters;
- `payload` entries refer to exact bytes in `payloads.json`;
- `symlink` and `reparse_point` entries model filesystem metadata and must be
  rejected without following the target.

A materializer must follow `fixture-contract-v1.json`. JSON documents are
encoded as RFC 8785 JSON Canonicalization Scheme bytes with no trailing
newline. `utf8` and payload entries are byte-for-byte. Case mutations are
applied to a group's base tree in order. Probe records are injected test
evidence for the tiny container stubs; they are never a substitute for
running `ffprobe` against real production media.

The payload catalog deliberately uses tiny recognizable bytes. Its JPEG and
MP4 payloads are boundary/hash stubs, not decodable quality samples. Codec,
full-decode, CRF, VMAF, SSIM, chroma, color-range, and CV regression gates
still require separately controlled real-camera corpora and are outside this
repository-sized contract suite.

## Signature and trust boundary

The valid signed cases contain a real Ed25519 signature over the exact
`signed_payload_utf8` bytes. The public key and fingerprint are recorded in
`trust/test-only-ed25519.json`; no private key is committed.

That key is a fixture-only identity. It is never trusted merely because it
is present in this directory or on a materialized card. A test that expects
`ready_signed` must explicitly inject the anchor named
`fixture-ed25519-2026-08-v1` into an isolated trust store. Without that
external injection, the identical cryptographically valid publication must
produce `waiting_for_pairing_key`. Production code must obtain trust from
the pairing/SAS workflow, never from card-provided key material.

The signed fixture layout intentionally exposes the same four values as the
existing LAN publication contract: exact signed payload bytes, detached
signature, presented public key, and externally expected key fingerprint.
An on-card parser may unwrap those values from the producer manifest, but it
must pass them through the existing publication trust boundary rather than
inventing a second verifier.

## Expected verdict rules

Every case has one expected result, except the valid signed publication which
has two explicit trust contexts:

- a valid signature plus the explicitly injected fixture anchor is
  `TrustedPublished` / `ready_signed`;
- a valid signature without a matching external anchor is
  `waiting_for_pairing_key`, not trusted;
- unsigned but structurally complete raw, v5, spool, unpublished v6, and
  `UnsignedPublicationV1` data
  are `ready_unsigned_requires_policy` with
  `locally_validated_unsigned` provenance;
- active, interrupted, failed, malformed, missing, duplicate, unclosed,
  conflicting, or hash-invalid inputs are recovery/diagnostic only;
- unknown major versions fail closed;
- unsafe paths and non-regular files fail before opening or following them.

Hash verification is against materialized bytes, not merely the manifest.
The `signed-v1-hash-mismatch-same-size` case swaps in a payload of exactly the
claimed size, proving that size equality alone is insufficient.

Every entry is a repository-authored synthetic contract fixture. It records no
real device, user, credential, or camera-capture claim. `raw_digest` is null
because raw source-card media is not retained; the materializer computes a
digest of the temporary virtual tree for each test run. These fixtures are
scanner/admission/recovery contracts only, not codec or quality evidence.

## Adding a fixture

1. Add immutable bytes to `payloads.json` when a new payload is needed.
2. Record byte length and lowercase SHA-256 over the decoded bytes.
3. Add a self-contained case or a base-tree mutation to the appropriate
   grouped case file.
4. Add exactly one index entry in `index.json`.
5. State the expected classifier, preflight verdict, provenance, stable error
   code, and whether normalization/upload are eligible.
6. Never add a real private signing key, credentials, device serials, MAC
   addresses, raw absolute mount paths, or user data.

Changing fixture semantics requires a new contract version. Existing case
IDs and payload IDs are immutable because durable recovery tests may persist
them as evidence.
