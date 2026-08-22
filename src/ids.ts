// Opaque identities.
//
// Every id in this app is a string on the wire, which is exactly why they used
// to be interchangeable: a device id, a session id, a library key and a job id
// all satisfied `string`, so passing the wrong one was a silent bug the type
// checker happily approved. Branding makes each one its own type. They still
// erase to strings at runtime (no wrapper objects, no allocation, JSON is
// unchanged), but nothing can flow into an identity parameter without being
// branded first.
//
// The brand is a `unique symbol` property that only exists in the type system,
// so the only way to obtain one is through the constructors below. Those
// constructors are the parse points: raw strings arriving from the DOM
// (`dataset.*`) or from the wire (`types.ts` DTOs, which stay plain strings
// because they mirror Rust's serde output) are branded there and nowhere else.
//
// Compile-fail examples — every line below is a type error, by design:
//
//   backend.listSessions(asSessionId("s1"));           // SessionId is not DeviceId
//   backend.cancelUpload(asDownloadJobId("job-1"));    // download id is not an upload id
//   backend.uploadEntry(asDeviceId("YLX-A"));          // DeviceId is not LibraryKey
//   backend.listSessions("YLX-A");                     // a bare string is not an identity

declare const idBrand: unique symbol;

type Branded<Kind extends string> = string & { readonly [idBrand]: Kind };

/** A LAN device's fingerprint. */
export type DeviceId = Branded<"DeviceId">;
/** A recording session on a device. */
export type SessionId = Branded<"SessionId">;
/** A file inside a session, as the Pi names it. */
export type FileId = Branded<"FileId">;
/** `deviceId|sessionId` — the local library's primary key. */
export type LibraryKey = Branded<"LibraryKey">;
/** A `TransferCoordinator` download job. */
export type DownloadJobId = Branded<"DownloadJobId">;
/** A durable upload job owned by TransferStore. */
export type UploadJobId = Branded<"UploadJobId">;
/** One pairing attempt; events carrying another one belong to a dead flow. */
export type PairingAttemptId = Branded<"PairingAttemptId">;

/** `retry_transfer` is the one command that accepts either direction. */
export type TransferRetryId = DownloadJobId | UploadJobId;

export function asDeviceId(raw: string): DeviceId {
  return raw as DeviceId;
}
export function asSessionId(raw: string): SessionId {
  return raw as SessionId;
}
export function asFileId(raw: string): FileId {
  return raw as FileId;
}
export function asLibraryKey(raw: string): LibraryKey {
  return raw as LibraryKey;
}
export function asDownloadJobId(raw: string): DownloadJobId {
  return raw as DownloadJobId;
}
export function asUploadJobId(raw: string): UploadJobId {
  return raw as UploadJobId;
}
export function asPairingAttemptId(raw: string): PairingAttemptId {
  return raw as PairingAttemptId;
}

/** The library key of a `deviceId`/`sessionId` pair. The one place the two
 * halves are joined, so the format cannot drift between call sites. */
export function libraryKeyOf(deviceId: string, sessionId: string): LibraryKey {
  return asLibraryKey(`${deviceId}|${sessionId}`);
}
