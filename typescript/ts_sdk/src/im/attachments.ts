import { createHash } from 'node:crypto';

import { validateDidDocumentBinding } from '../authentication/did-wba.js';
import type { DidDocument } from '../authentication/types.js';
import { AwikiImError } from './errors.js';
import type { AwikiIdentityRuntime } from './identity.js';
import type {
  PersistedAttachmentReference,
  PersistedAttachmentSendOperation,
  PersistedAttachmentSlot,
} from './internal.js';
import {
  assertOperationFingerprint,
  sendFingerprint,
  sendOperationKey,
  type AwikiMessagingRuntime,
} from './messaging.js';
import type { AwikiImStateStore } from './storage.js';
import { operationId, type AwikiImTransport } from './protocol.js';
import type {
  AwikiAttachmentId,
  DownloadAwikiAttachmentRequest,
  DownloadedAwikiAttachment,
  SendAwikiAttachmentRequest,
  AwikiMessage,
} from './types.js';

const ATTACHMENT_PROFILE = 'anp.attachment.v1';
const ATTACHMENT_CONTENT_TYPE = 'application/anp-attachment-manifest+json';

interface AttachmentRuntimeOptions {
  readonly transport: AwikiImTransport;
  readonly store: AwikiImStateStore;
  readonly identity: AwikiIdentityRuntime;
  readonly messaging: AwikiMessagingRuntime;
  readonly attachmentMaxBytes: number;
}

/** Single-object P7 upload, attachment message, ticket, and verified download operations. */
export class AwikiAttachmentRuntime {
  public constructor(private readonly options: AttachmentRuntimeOptions) {}

  /** Upload, commit, and send one attachment manifest. */
  public async sendAttachment(request: SendAwikiAttachmentRequest): Promise<AwikiMessage> {
    return this.options.messaging.exclusiveSend(async () => {
      validateUpload(request.attachment, this.options.attachmentMaxBytes);
      const prepared = prepareAttachment(request.attachment.bytes);
      const caption = request.caption?.trim() || undefined;
      const fingerprint = sendFingerprint({
        kind: 'attachment',
        target: request.target,
        fileName: request.attachment.fileName,
        mimeType: request.attachment.mimeType,
        size: request.attachment.bytes.byteLength,
        digest: prepared.digestHex,
        caption,
      });
      const key = sendOperationKey(request.idempotencyKey);
      const existing = this.options.store.snapshot().sendOperations[key];
      if (existing) {
        assertOperationFingerprint(existing.kind, existing.fingerprint, 'attachment', fingerprint);
        if (existing.kind !== 'attachment') {
          throw new AwikiImError('conflict', 'AWiki idempotency key is already in use');
        }
        if (existing.stage === 'completed' && existing.result) {
          return structuredClone(existing.result);
        }
        return this.resumeAttachmentSend(key, existing, request.attachment.bytes);
      }

      const target = await this.options.messaging.resolveTarget(request.target);
      const identifiers = attachmentIdentifiers(request.idempotencyKey);
      const now = new Date().toISOString();
      const operation: PersistedAttachmentSendOperation = {
        kind: 'attachment',
        fingerprint,
        target,
        attachment: {
          id: identifiers.attachmentId as AwikiAttachmentId,
          fileName: request.attachment.fileName,
          mimeType: request.attachment.mimeType,
          size: request.attachment.bytes.byteLength,
          sha256: prepared.digestHex,
        },
        digestB64u: prepared.digestB64u,
        ...(caption ? { caption } : {}),
        createOperationId: identifiers.createOperationId,
        commitOperationId: identifiers.commitOperationId,
        messageOperationId: identifiers.messageOperationId,
        messageId: identifiers.messageId,
        createCreatedAt: now,
        commitCreatedAt: now,
        messageCreatedAt: now,
        stage: 'prepared',
      };
      await this.options.store.mutate((state) => {
        if (state.sendOperations[key]) {
          throw new AwikiImError('conflict', 'AWiki idempotency key is already in use');
        }
        state.sendOperations[key] = operation;
      });
      return this.resumeAttachmentSend(key, operation, request.attachment.bytes);
    });
  }

  private async resumeAttachmentSend(
    key: string,
    initial: PersistedAttachmentSendOperation,
    bytes: Uint8Array
  ): Promise<AwikiMessage> {
    const identity = this.options.identity.requireSecrets();
    let operation = initial;
    if (operation.stage === 'prepared') {
      const slotResult = await this.options.messaging.authenticatedRpc('attachment.create_slot', {
        meta: attachmentMeta(
          identity.public.did as string,
          identity.messageServiceDid,
          operation.createOperationId,
          operation.createCreatedAt
        ),
        body: {
          attachment_id: operation.attachment.id as string,
          expected_size: String(operation.attachment.size),
          expected_digest: { alg: 'sha-256', value_b64u: operation.digestB64u },
          mime_type: operation.attachment.mimeType,
          filename: operation.attachment.fileName,
          intended_message_security_profile: 'transport-protected',
          intended_target: {
            kind: operation.target.kind === 'direct' ? 'agent' : 'group',
            did: operation.target.did,
          },
          object_encryption_mode: 'none',
        },
      });
      const slot = parseSlot(slotResult, operation.attachment.id as string);
      this.options.transport.validateAttachmentUrl(slot.uploadUri);
      this.options.transport.validateAttachmentUrl(slot.objectUri);
      operation = await this.advanceOperation(key, operation, { stage: 'slot-created', slot });
    }
    const slot = requiredSlot(operation);
    if (operation.stage === 'slot-created') {
      await this.options.transport.putBytes(slot.uploadUri, slot.uploadHeaders, bytes);
      operation = await this.advanceOperation(key, operation, { stage: 'uploaded' });
    }
    if (operation.stage === 'uploaded') {
      const commit = await this.options.messaging.authenticatedRpc('attachment.commit_object', {
        meta: attachmentMeta(
          identity.public.did as string,
          identity.messageServiceDid,
          operation.commitOperationId,
          operation.commitCreatedAt
        ),
        body: {
          attachment_id: operation.attachment.id as string,
          slot_id: slot.slotId,
          commit_token: slot.commitToken,
          size: String(operation.attachment.size),
          digest: { alg: 'sha-256', value_b64u: operation.digestB64u },
          object_encryption_mode: 'none',
        },
      });
      if (
        commit.committed !== true ||
        commit.attachment_id !== operation.attachment.id ||
        commit.object_uri !== slot.objectUri
      ) {
        throw new AwikiImError('remote', 'AWiki attachment commit acknowledgement is invalid');
      }
      operation = await this.advanceOperation(key, operation, { stage: 'committed' });
    }
    if (operation.stage !== 'committed') {
      if (operation.stage === 'completed' && operation.result) return operation.result;
      throw new AwikiImError('remote', 'AWiki attachment send state is invalid');
    }
    const manifest = {
      attachments: [
        {
          attachment_id: operation.attachment.id as string,
          filename: operation.attachment.fileName,
          mime_type: operation.attachment.mimeType,
          size: String(operation.attachment.size),
          digest: { alg: 'sha-256', value_b64u: operation.digestB64u },
          access_info: { object_uri: slot.objectUri },
          encryption_info: { mode: 'none' },
        },
      ],
      ...(operation.caption ? { caption: operation.caption } : {}),
      primary_attachment_id: operation.attachment.id as string,
    };
    const reference: Omit<PersistedAttachmentReference, 'messageId'> = {
      attachment: operation.attachment,
      objectUri: slot.objectUri,
      senderDid: identity.public.did as string,
      ...(operation.target.kind === 'group'
        ? { groupDid: operation.target.did }
        : { messageTargetDid: operation.target.did }),
      messageServiceDid: identity.messageServiceDid,
    };
    const message = await this.options.messaging.sendPayload(
      operation.target,
      ATTACHMENT_CONTENT_TYPE,
      { payload: manifest },
      {
        operationId: operation.messageOperationId,
        messageId: operation.messageId,
        createdAt: operation.messageCreatedAt,
      },
      {
        kind: 'attachment',
        attachment: operation.attachment,
        ...(operation.caption ? { caption: operation.caption } : {}),
      },
      reference
    );
    await this.advanceOperation(key, operation, { stage: 'completed', result: message });
    return message;
  }

  private async advanceOperation(
    key: string,
    expected: PersistedAttachmentSendOperation,
    patch: Partial<PersistedAttachmentSendOperation>
  ): Promise<PersistedAttachmentSendOperation> {
    let updated: PersistedAttachmentSendOperation | undefined;
    await this.options.store.mutate((state) => {
      const current = state.sendOperations[key];
      if (
        !current ||
        current.kind !== 'attachment' ||
        current.fingerprint !== expected.fingerprint ||
        current.stage !== expected.stage
      ) {
        throw new AwikiImError('conflict', 'AWiki attachment send operation state changed');
      }
      updated = { ...current, ...patch } as PersistedAttachmentSendOperation;
      state.sendOperations[key] = updated;
    });
    if (!updated) {
      throw new AwikiImError('remote', 'AWiki attachment send state was not persisted');
    }
    return updated;
  }

  /** Issue a ticket, download the object, and verify exact size and SHA-256. */
  public async downloadAttachment(
    request: DownloadAwikiAttachmentRequest
  ): Promise<DownloadedAwikiAttachment> {
    const identity = this.options.identity.requireSecrets();
    const references = Object.values(this.options.store.snapshot().attachments).filter(
      (candidate) =>
        candidate.attachment.id === request.attachmentId &&
        candidate.messageId === request.messageId
    );
    if (references.length === 0) {
      throw new AwikiImError('not-found', 'AWiki attachment was not found');
    }
    if (references.length > 1) {
      throw new AwikiImError('conflict', 'AWiki attachment message reference is ambiguous');
    }
    const reference = references[0];
    if (!reference) {
      throw new AwikiImError('not-found', 'AWiki attachment was not found');
    }
    this.options.transport.validateAttachmentUrl(reference.objectUri);
    const operation = operationId('op');
    const messageServiceDid = await this.resolveAttachmentServiceDid(reference.senderDid);
    const ticket = await this.options.messaging.authenticatedRpc('attachment.get_download_ticket', {
      meta: attachmentMeta(
        identity.public.did as string,
        messageServiceDid,
        operation,
        new Date().toISOString()
      ),
      body: {
        attachment_id: reference.attachment.id as string,
        object_uri: reference.objectUri,
        requester_did: identity.public.did as string,
        message_security_profile: 'transport-protected',
        message_id: reference.messageId,
        one_time: true,
        ...(reference.groupDid
          ? { group_did: reference.groupDid }
          : { message_target_did: requiredDirectTarget(reference) }),
      },
    });
    validateTicketBinding(ticket.ticket_binding, reference, identity.public.did as string);
    const ticketValue = requiredString(ticket.download_ticket_b64u, 'download ticket');
    const bytes = await this.options.transport.getBytes(
      reference.objectUri,
      ticketValue,
      reference.attachment.size
    );
    const digestHex = createHash('sha256').update(bytes).digest('hex');
    if (
      bytes.byteLength !== reference.attachment.size ||
      digestHex !== reference.attachment.sha256
    ) {
      throw new AwikiImError('remote', 'AWiki attachment verification failed');
    }
    return { attachment: reference.attachment, bytes };
  }

  private async resolveAttachmentServiceDid(senderDid: string): Promise<string> {
    const identity = this.options.identity.requireSecrets();
    const document =
      senderDid === identity.public.did
        ? (identity.didDocument as unknown as Record<string, unknown>)
        : await this.options.transport.getJson(didResolutionUrl(senderDid));
    if (document.id !== senderDid) {
      throw new AwikiImError('remote', 'AWiki service returned an invalid response');
    }
    if (!isValidAttachmentDidDocument(document)) {
      throw new AwikiImError('remote', 'AWiki attachment sender DID document is invalid');
    }
    const matching = arrayValue(document.service)
      .filter(isRecord)
      .filter(
        (service) =>
          service.type === 'ANPMessageService' &&
          arrayValue(service.profiles).includes(ATTACHMENT_PROFILE) &&
          arrayValue(service.securityProfiles ?? service.security_profiles).includes(
            'transport-protected'
          ) &&
          typeof service.serviceDid === 'string' &&
          service.serviceDid.trim() &&
          typeof service.serviceEndpoint === 'string' &&
          service.serviceEndpoint.trim()
      )
      .map((service, index) => ({
        service,
        index,
        priority: priorityValue(service.priority),
      }))
      .sort((left, right) => {
        if (left.priority !== undefined && right.priority !== undefined) {
          return left.priority - right.priority || left.index - right.index;
        }
        if (left.priority !== undefined) return -1;
        if (right.priority !== undefined) return 1;
        return left.index - right.index;
      });
    const selected = matching[0]?.service;
    if (!selected) {
      throw new AwikiImError('remote', 'AWiki attachment service was not found');
    }
    this.options.transport.validateAttachmentUrl(
      requiredString(selected.serviceEndpoint, 'attachment service endpoint')
    );
    return requiredString(selected.serviceDid, 'attachment service DID');
  }
}

type AttachmentSlot = PersistedAttachmentSlot;

function requiredSlot(operation: PersistedAttachmentSendOperation): PersistedAttachmentSlot {
  if (!operation.slot) {
    throw new AwikiImError('remote', 'AWiki attachment slot state is missing');
  }
  return operation.slot;
}

function parseSlot(result: Record<string, unknown>, expectedAttachmentId: string): AttachmentSlot {
  const attachmentId = requiredString(result.attachment_id, 'attachment ID');
  if (attachmentId !== expectedAttachmentId) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response');
  }
  return {
    attachmentId,
    slotId: requiredString(result.slot_id, 'attachment slot ID'),
    uploadUri: requiredString(result.upload_uri, 'attachment upload URI'),
    uploadHeaders: stringRecord(result.upload_headers, 'attachment upload headers'),
    objectUri: requiredString(result.object_uri, 'attachment object URI'),
    commitToken: requiredString(result.commit_token, 'attachment commit token'),
  };
}

function attachmentMeta(
  senderDid: string,
  serviceDid: string,
  operation: string,
  createdAt: string
): Record<string, unknown> {
  return {
    profile: ATTACHMENT_PROFILE,
    security_profile: 'transport-protected',
    sender_did: senderDid,
    target: { kind: 'service', did: serviceDid },
    operation_id: operation,
    created_at: createdAt,
  };
}

function attachmentIdentifiers(idempotencyKey: string): {
  readonly attachmentId: string;
  readonly createOperationId: string;
  readonly commitOperationId: string;
  readonly messageOperationId: string;
  readonly messageId: string;
} {
  const key = idempotencyKey.trim();
  if (!key || key.length > 256) {
    throw new AwikiImError('invalid-request', 'AWiki idempotency key is invalid');
  }
  return {
    attachmentId: `att-${digestPrefix(`attachment:${key}`)}`,
    createOperationId: `op-${digestPrefix(`create:${key}`)}`,
    commitOperationId: `op-${digestPrefix(`commit:${key}`)}`,
    messageOperationId: `op-${digestPrefix(`message:${key}`)}`,
    messageId: `msg-${digestPrefix(`message:${key}`)}`,
  };
}

function digestPrefix(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 32);
}

function prepareAttachment(bytes: Uint8Array): {
  readonly digestHex: string;
  readonly digestB64u: string;
} {
  const digest = createHash('sha256').update(bytes).digest();
  return { digestHex: digest.toString('hex'), digestB64u: digest.toString('base64url') };
}

function validateUpload(
  upload: {
    readonly fileName: string;
    readonly mimeType: string;
    readonly bytes: Uint8Array;
  },
  maximumBytes: number
): void {
  if (!upload.fileName.trim() || upload.fileName.includes('/') || upload.fileName.includes('\\')) {
    throw new AwikiImError('invalid-request', 'AWiki attachment file name is invalid');
  }
  if (!/^[\w.+-]+\/[\w.+-]+$/.test(upload.mimeType.trim())) {
    throw new AwikiImError('invalid-request', 'AWiki attachment MIME type is invalid');
  }
  if (!(upload.bytes instanceof Uint8Array)) {
    throw new AwikiImError('invalid-request', 'AWiki attachment bytes are invalid');
  }
  if (upload.bytes.byteLength > maximumBytes) {
    throw new AwikiImError('invalid-request', 'AWiki attachment exceeds the configured limit');
  }
}

function validateTicketBinding(
  value: unknown,
  reference: PersistedAttachmentReference,
  requesterDid: string
): void {
  if (!isRecord(value)) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response');
  }
  const expected = {
    attachment_id: reference.attachment.id as string,
    object_uri: reference.objectUri,
    requester_did: requesterDid,
    message_id: reference.messageId,
    message_security_profile: 'transport-protected',
  };
  if (
    Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue) ||
    (reference.groupDid
      ? value.group_did !== reference.groupDid
      : value.message_target_did !== reference.messageTargetDid)
  ) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response');
  }
}

function requiredDirectTarget(reference: PersistedAttachmentReference): string {
  if (!reference.messageTargetDid) {
    throw new AwikiImError('not-found', 'AWiki attachment message context was not found');
  }
  return reference.messageTargetDid;
}

function didResolutionUrl(did: string): string {
  if (!did.startsWith('did:wba:')) {
    throw new AwikiImError('remote', 'AWiki attachment sender DID is invalid');
  }
  const parts = did.split(':');
  const authority = parts[2];
  if (!authority) {
    throw new AwikiImError('remote', 'AWiki attachment sender DID is invalid');
  }
  const host = decodeURIComponent(authority);
  const path = parts
    .slice(3)
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  return path ? `https://${host}/${path}/did.json` : `https://${host}/.well-known/did.json`;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new AwikiImError('remote', `AWiki response is missing ${label}`);
  }
  return value.trim();
}

function stringRecord(value: unknown, label: string): Record<string, string> {
  if (!isRecord(value)) {
    throw new AwikiImError('remote', `AWiki response is missing ${label}`);
  }
  const output: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value)) {
    if (typeof headerValue !== 'string' || !key.trim()) {
      throw new AwikiImError('remote', `AWiki response is missing ${label}`);
    }
    output[key] = headerValue;
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function arrayValue(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

function priorityValue(value: unknown): number | undefined {
  const parsed =
    typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

function isValidAttachmentDidDocument(document: Record<string, unknown>): boolean {
  try {
    return validateDidDocumentBinding(document as unknown as DidDocument, true);
  } catch {
    return false;
  }
}
