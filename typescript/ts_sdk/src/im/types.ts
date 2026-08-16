/** Public, high-level AWiki IM client types. */

declare const AWIKI_IM_ID: unique symbol;

/** String identifier that remains nominally distinct across IM domains. */
export type AwikiImId<Kind extends string> = string & {
  readonly [AWIKI_IM_ID]: Kind;
};

/** Stable AWiki decentralized identifier. */
export type AwikiDid = AwikiImId<'did'>;

/** Validated AWiki handle. */
export type AwikiHandle = AwikiImId<'handle'>;

/** Stable conversation identifier. */
export type AwikiConversationId = AwikiImId<'conversation'>;

/** Stable message identifier. */
export type AwikiMessageId = AwikiImId<'message'>;

/** Stable attachment identifier. */
export type AwikiAttachmentId = AwikiImId<'attachment'>;

/** Opaque pagination cursor returned by AWiki. */
export type AwikiCursor = AwikiImId<'cursor'>;

/** Persisted identity metadata. Private keys and access tokens are excluded. */
export interface AwikiIdentity {
  readonly handle: AwikiHandle;
  readonly did: AwikiDid;
  /** WNS `profile.display_name`. Display-only; never used for routing. */
  readonly displayName?: string;
  readonly registeredAt: number;
}

/** Public peer produced by Handle lookup or a DID target. */
export interface AwikiResolvedPeer {
  readonly did: AwikiDid;
  readonly handle?: AwikiHandle;
  /** WNS `profile.display_name`. Display-only; never used for routing. */
  readonly displayName?: string;
  readonly conversationId: AwikiConversationId;
}

/** Request for one registration verification code. */
export interface SendRegistrationOtpRequest {
  readonly handle: string;
  readonly phone: string;
}

/** Server-issued registration challenge metadata. */
export interface SendRegistrationOtpResult {
  readonly retryAfterSeconds: number;
  readonly retryAt: string;
}

/** Complete a new identity registration from a verified phone challenge. */
export interface RegisterIdentityRequest {
  readonly handle: string;
  readonly phone: string;
  readonly otp: string;
}

/** Replace the registered identity's public WNS display name. */
export interface UpdateAwikiDisplayNameRequest {
  readonly displayName: string;
}

/** Existing direct-message conversation. */
export interface AwikiDirectConversation {
  readonly kind: 'direct';
  readonly id: AwikiConversationId;
  readonly peerDid: AwikiDid;
  readonly peerHandle?: AwikiHandle;
  /** WNS `profile.display_name`. Display-only; never used for routing. */
  readonly displayName?: string;
  readonly title: string;
  /** Current unread inbox messages for this conversation. */
  readonly unreadCount?: number;
  readonly lastMessageAt?: number;
  /** Display-only summary of the newest observed message. */
  readonly lastMessagePreview?: string;
}

/** Existing group conversation. */
export interface AwikiGroupConversation {
  readonly kind: 'group';
  readonly id: AwikiConversationId;
  readonly groupDid: AwikiDid;
  readonly title: string;
  /** Current unread inbox messages for this conversation. */
  readonly unreadCount?: number;
  readonly lastMessageAt?: number;
  /** Display-only summary of the newest observed message. */
  readonly lastMessagePreview?: string;
}

/** Conversation visible to the registered identity. */
export type AwikiConversation = AwikiDirectConversation | AwikiGroupConversation;

/** Direct-message destination resolved by handle or DID. */
export interface AwikiDirectTarget {
  readonly kind: 'direct';
  readonly peer: string;
}

/** Existing group destination. Group creation is outside this API. */
export interface AwikiGroupTarget {
  readonly kind: 'group';
  readonly group: string;
}

/** Destination accepted by text and attachment sends. */
export type AwikiMessageTarget = AwikiDirectTarget | AwikiGroupTarget;

/** Attachment metadata safe to expose to an IM SDK consumer. */
export interface AwikiAttachment {
  readonly id: AwikiAttachmentId;
  readonly fileName: string;
  readonly mimeType: string;
  readonly size: number;
  readonly sha256: string;
}

/** Plain text message content. */
export interface AwikiTextContent {
  readonly kind: 'text';
  readonly text: string;
}

/** Attachment message content. */
export interface AwikiAttachmentContent {
  readonly kind: 'attachment';
  readonly attachment: AwikiAttachment;
  readonly caption?: string;
}

/** Content types supported by the first AWiki Harness integration. */
export type AwikiMessageContent = AwikiTextContent | AwikiAttachmentContent;

/** One direct or group message. */
export interface AwikiMessage {
  readonly id: AwikiMessageId;
  readonly conversationId: AwikiConversationId;
  readonly conversationKind: AwikiConversation['kind'];
  readonly senderDid: AwikiDid;
  readonly senderHandle?: AwikiHandle;
  /** WNS `profile.display_name` for the sender. Display-only; never used for routing. */
  readonly senderDisplayName?: string;
  readonly sentAt: number;
  readonly outgoing: boolean;
  readonly content: AwikiMessageContent;
}

/** One immutable page from an AWiki collection. */
export interface AwikiPage<Item> {
  readonly items: readonly Item[];
  readonly nextCursor?: AwikiCursor;
  readonly hasMore: boolean;
}

/** Common cursor request for conversation and history reads. */
export interface AwikiPageRequest {
  readonly cursor?: AwikiCursor;
  readonly limit?: number;
}

/** Request for one conversation's message history. */
export interface GetAwikiHistoryRequest extends AwikiPageRequest {
  readonly conversationId: AwikiConversationId;
}

/** Send one plain text message. */
export interface SendAwikiTextRequest {
  readonly target: AwikiMessageTarget;
  readonly text: string;
  readonly idempotencyKey: string;
}

/** Bytes and public metadata for one attachment upload. */
export interface AwikiUpload {
  readonly fileName: string;
  readonly mimeType: string;
  readonly bytes: Uint8Array;
}

/** Upload and send one attachment message. */
export interface SendAwikiAttachmentRequest {
  readonly target: AwikiMessageTarget;
  readonly attachment: AwikiUpload;
  readonly caption?: string;
  readonly idempotencyKey: string;
}

/** Download request for one attachment visible to the current identity. */
export interface DownloadAwikiAttachmentRequest {
  readonly attachmentId: AwikiAttachmentId;
  readonly messageId: AwikiMessageId;
}

/** Verified attachment bytes and public metadata. */
export interface DownloadedAwikiAttachment {
  readonly attachment: AwikiAttachment;
  readonly bytes: Uint8Array;
}

/** Stable public error categories normalized from AWiki services. */
export type AwikiImErrorCode =
  | 'not-registered'
  | 'already-registered'
  | 'invalid-request'
  | 'invalid-otp'
  | 'challenge-expired'
  | 'handle-unavailable'
  | 'not-found'
  | 'forbidden'
  | 'conflict'
  | 'rate-limited'
  | 'network'
  | 'remote';

/** Options for the Node.js AWiki IM client. */
export interface AwikiImClientOptions {
  readonly userServiceUrl: string;
  /** Handle domain administered by the User Service; it need not equal the service URL host. */
  readonly userServiceDomain: string;
  readonly messageServiceUrl: string;
  /** Public Message Service base URL advertised in the identity DID document. */
  readonly messageServicePublicUrl: string;
  /** Authoritative Home Message Service DID advertised in the registered DID document. */
  readonly messageServiceDid: string;
  /** Exact HTTPS origins permitted for DID discovery, attachment service endpoints, and objects. */
  readonly allowedAttachmentOrigins: readonly string[];
  /** Maximum attachment size accepted for both upload and download. */
  readonly attachmentMaxBytes: number;
  /** Permit HTTP loopback URLs only in an explicitly controlled test environment. */
  readonly allowInsecureLoopbackForTesting?: boolean;
  readonly statePath: string;
  readonly fetch?: typeof globalThis.fetch;
}

/**
 * High-level AWiki IM API. Implementations own credentials, request signing,
 * handle resolution, pagination, idempotency, attachment transfer, and
 * persistent identity state.
 */
export interface AwikiImClient {
  /** Return the persisted default identity without exposing secret material. */
  getIdentity(): Promise<AwikiIdentity | null>;
  /** Send one phone verification code for registration. */
  sendRegistrationOtp(request: SendRegistrationOtpRequest): Promise<SendRegistrationOtpResult>;
  /** Register and persist the deployment's only identity. */
  registerIdentity(request: RegisterIdentityRequest): Promise<AwikiIdentity>;
  /** Update and persist the registered identity's public WNS display name. */
  updateDisplayName(request: UpdateAwikiDisplayNameRequest): Promise<AwikiIdentity>;
  /** Resolve one Handle or DID to a public peer and persist the direct conversation row. */
  resolvePeer(peer: string): Promise<AwikiResolvedPeer>;
  /** List direct and existing group conversations. */
  listConversations(request?: AwikiPageRequest): Promise<AwikiPage<AwikiConversation>>;
  /** Read one conversation's paginated history. */
  getHistory(request: GetAwikiHistoryRequest): Promise<AwikiPage<AwikiMessage>>;
  /** Mark every currently unread inbox message in one conversation as read. */
  markConversationRead(conversationId: AwikiConversationId): Promise<number>;
  /** Send one idempotent text message. */
  sendText(request: SendAwikiTextRequest): Promise<AwikiMessage>;
  /** Upload and send one idempotent attachment message. */
  sendAttachment(request: SendAwikiAttachmentRequest): Promise<AwikiMessage>;
  /** Download and verify one attachment before returning its bytes. */
  downloadAttachment(request: DownloadAwikiAttachmentRequest): Promise<DownloadedAwikiAttachment>;
  /** Stop background work and release owned resources. */
  dispose(): Promise<void>;
}
