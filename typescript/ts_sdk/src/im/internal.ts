import type { DidDocument } from '../authentication/types.js';
import type {
  AwikiAttachment,
  AwikiConversation,
  AwikiConversationId,
  AwikiIdentity,
  AwikiMessage,
} from './types.js';

export const STATE_VERSION = 2;
export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 100;

export interface RegistrationOtpState {
  readonly handle: string;
  readonly phone: string;
  readonly retryAt: string;
}

export interface PersistedIdentitySecrets {
  readonly public: AwikiIdentity;
  readonly didDocument: DidDocument;
  readonly rootPrivateKeyPem: string;
  readonly signingPrivateKeyPem: string;
  readonly signingKeyId: string;
  readonly accessToken: string;
  readonly messageServiceDid: string;
}

export interface PendingRegistrationState {
  readonly handle: string;
  readonly phone: string;
  readonly didDocument: DidDocument;
  readonly rootPrivateKeyPem: string;
  readonly signingPrivateKeyPem: string;
  readonly signingKeyId: string;
  readonly messageServiceDid: string;
}

export interface PersistedConversation {
  readonly conversation: AwikiConversation;
  readonly peerDid?: string;
  readonly groupDid?: string;
}

export interface PersistedAttachmentReference {
  readonly attachment: AwikiAttachment;
  readonly objectUri: string;
  readonly senderDid: string;
  readonly messageId: string;
  readonly messageTargetDid?: string;
  readonly groupDid?: string;
  readonly messageServiceDid: string;
}

export interface PersistedSendTarget {
  readonly kind: 'direct' | 'group';
  readonly did: string;
  readonly handle?: string;
  readonly conversationId: AwikiConversationId;
}

export interface PersistedTextSendOperation {
  readonly kind: 'text';
  readonly fingerprint: string;
  readonly target: PersistedSendTarget;
  readonly createdAt: string;
  readonly operationId: string;
  readonly messageId: string;
  readonly text: string;
  readonly stage: 'prepared' | 'completed';
  readonly result?: AwikiMessage;
}

export interface PersistedAttachmentSlot {
  readonly attachmentId: string;
  readonly slotId: string;
  readonly uploadUri: string;
  readonly uploadHeaders: Record<string, string>;
  readonly objectUri: string;
  readonly commitToken: string;
}

export interface PersistedAttachmentSendOperation {
  readonly kind: 'attachment';
  readonly fingerprint: string;
  readonly target: PersistedSendTarget;
  readonly attachment: AwikiAttachment;
  readonly digestB64u: string;
  readonly caption?: string;
  readonly createOperationId: string;
  readonly commitOperationId: string;
  readonly messageOperationId: string;
  readonly messageId: string;
  readonly createCreatedAt: string;
  readonly commitCreatedAt: string;
  readonly messageCreatedAt: string;
  readonly stage: 'prepared' | 'slot-created' | 'uploaded' | 'committed' | 'completed';
  readonly slot?: PersistedAttachmentSlot;
  readonly result?: AwikiMessage;
}

export type PersistedSendOperation = PersistedTextSendOperation | PersistedAttachmentSendOperation;

export interface PersistedImState {
  readonly version: typeof STATE_VERSION;
  registrationOtp?: RegistrationOtpState;
  pendingRegistration?: PendingRegistrationState;
  identity?: PersistedIdentitySecrets;
  conversations: Record<string, PersistedConversation>;
  attachments: Record<string, PersistedAttachmentReference>;
  sendOperations: Record<string, PersistedSendOperation>;
}

export interface JsonRpcErrorValue {
  readonly code?: number;
  readonly message?: string;
  readonly data?: unknown;
}

export interface MessageWireValue {
  readonly [key: string]: unknown;
}

export function emptyState(): PersistedImState {
  return {
    version: STATE_VERSION,
    conversations: {},
    attachments: {},
    sendOperations: {},
  };
}

export function conversationKey(id: AwikiConversationId): string {
  return id as string;
}
