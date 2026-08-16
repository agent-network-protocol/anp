import { createHash } from 'node:crypto';

import { canonicalizeJson } from '../internal/json.js';
import { AwikiImError, normalizeAwikiImError } from './errors.js';
import {
  DEFAULT_PAGE_LIMIT,
  MAX_PAGE_LIMIT,
  conversationKey,
  type MessageWireValue,
  type PersistedAttachmentReference,
  type PersistedConversation,
  type PersistedTextSendOperation,
} from './internal.js';
import {
  buildOriginAuthentication,
  HANDLE_RPC_PATH,
  MESSAGE_RPC_PATH,
  operationId,
} from './protocol.js';
import { handleCandidateFromDid, lookupDisplayName } from './display-name.js';
import type { AwikiIdentityRuntime } from './identity.js';
import type { AwikiImStateStore } from './storage.js';
import type { AwikiImTransport } from './protocol.js';
import type {
  AwikiAttachment,
  AwikiAttachmentId,
  AwikiConversation,
  AwikiConversationId,
  AwikiCursor,
  AwikiDid,
  AwikiHandle,
  AwikiMessage,
  AwikiMessageContent,
  AwikiMessageId,
  AwikiMessageTarget,
  AwikiPage,
  AwikiPageRequest,
  GetAwikiHistoryRequest,
  SendAwikiTextRequest,
} from './types.js';

interface MessagingRuntimeOptions {
  readonly userServiceUrl: string;
  readonly messageServiceUrl: string;
  readonly transport: AwikiImTransport;
  readonly store: AwikiImStateStore;
  readonly identity: AwikiIdentityRuntime;
  readonly attachmentMaxBytes: number;
}

const MAX_REFRESH_PAGES = 1_000;

export interface ResolvedMessageTarget {
  readonly kind: 'direct' | 'group';
  readonly did: string;
  readonly handle?: string;
  readonly displayName?: string;
  readonly conversationId: AwikiConversationId;
}

/** Direct/group conversation, history, and plain-message operations. */
export class AwikiMessagingRuntime {
  private sendTail: Promise<void> = Promise.resolve();
  private inboxRefreshed = false;
  private unreadMessageIds = new Map<string, readonly string[]>();
  private groupUnreadMessageIds = new Map<string, readonly string[]>();
  private groupMessageWindows = new Map<string, ReadonlySet<string>>();

  public constructor(private readonly options: MessagingRuntimeOptions) {}

  /** Refresh conversation records and return one local page. */
  public async listConversations(
    request: AwikiPageRequest = {}
  ): Promise<AwikiPage<AwikiConversation>> {
    this.options.identity.requireSecrets();
    const limit = pageLimit(request.limit);
    await this.refreshConversations();
    await this.hydrateGroupMessagePreviews();
    await this.hydrateDirectDisplayNames();
    const conversations = Object.values(this.options.store.snapshot().conversations)
      .map((record) => {
        const key = conversationKey(record.conversation.id);
        const unreadCount = new Set([
          ...(this.unreadMessageIds.get(key) ?? []),
          ...(this.groupUnreadMessageIds.get(key) ?? []),
        ]).size;
        return { ...record.conversation, unreadCount };
      })
      .sort(compareConversationRecency);
    const offset = decodeOffsetCursor(request.cursor);
    const items = conversations.slice(offset, offset + limit);
    const nextOffset = offset + items.length;
    return {
      items,
      hasMore: nextOffset < conversations.length,
      ...(nextOffset < conversations.length ? { nextCursor: encodeOffsetCursor(nextOffset) } : {}),
    };
  }

  /** Read and normalize one direct/group history page using the service's offset support. */
  public async getHistory(request: GetAwikiHistoryRequest): Promise<AwikiPage<AwikiMessage>> {
    const record =
      this.options.store.snapshot().conversations[conversationKey(request.conversationId)];
    if (!record) {
      throw new AwikiImError('not-found', 'AWiki conversation was not found');
    }
    const identity = this.options.identity.requireSecrets();
    const limit = pageLimit(request.limit);
    const kind = record.conversation.kind;
    const skip = decodeHistoryCursor(request.cursor, kind, request.conversationId);
    const result =
      kind === 'direct'
        ? await this.authenticatedRpc('direct.get_history', {
            meta: localMeta(identity.public.did as string, 'anp.direct.local.v1'),
            body: compactRecord({
              user_did: identity.public.did as string,
              peer_did: requiredConversationValue(record.peerDid),
              limit,
              skip: skip || undefined,
            }),
          })
        : await this.authenticatedRpc('group.list_messages', {
            meta: groupLocalMeta(
              identity.public.did as string,
              requiredConversationValue(record.groupDid)
            ),
            body: compactRecord({
              group_did: requiredConversationValue(record.groupDid),
              limit,
              skip: skip || undefined,
            }),
          });
    const wires = arrayValue(result.messages);
    validateHistoryWires(wires, record, identity.public.did as string);
    const mapped = wires
      .map((wire) =>
        isRecord(wire)
          ? this.mapWireMessage(wire, record.conversation, identity.public.did as string)
          : null
      )
      .filter((message): message is MappedMessage => message !== null);
    const hydrated = await this.hydrateGroupSenderDisplayNames(mapped);
    await this.persistMappedMessages(hydrated);
    const items = hydrated.map((entry) => entry.message).sort(compareMessageTime);
    const consumed = wires.length;
    if (result.has_more === true && consumed === 0) {
      throw new AwikiImError('remote', 'AWiki history pagination did not advance');
    }
    const hasMore = result.has_more === true;
    return {
      items,
      hasMore,
      ...(hasMore
        ? { nextCursor: encodeHistoryCursor(kind, request.conversationId, skip + consumed) }
        : {}),
    };
  }

  /** Mark every currently unread inbox message in one conversation as read. */
  public async markConversationRead(conversationId: AwikiConversationId): Promise<number> {
    const key = conversationKey(conversationId);
    if (!this.options.store.snapshot().conversations[key]) {
      throw new AwikiImError('not-found', 'AWiki conversation was not found');
    }
    if (!this.inboxRefreshed) {
      await this.refreshInbox();
    }
    const messageIds = this.unreadMessageIds.get(key) ?? [];
    const localGroupMessageIds = this.groupUnreadMessageIds.get(key) ?? [];
    if (messageIds.length === 0 && localGroupMessageIds.length === 0) {
      return 0;
    }
    let updatedCount = 0;
    if (messageIds.length > 0) {
      const identity = this.options.identity.requireSecrets();
      const result = await this.authenticatedRpc('inbox.mark_read', {
        meta: localMeta(identity.public.did as string, 'anp.inbox.local.v1'),
        body: {
          user_did: identity.public.did as string,
          message_ids: [...messageIds],
        },
      });
      updatedCount = integerValue(result.updated_count) ?? -1;
      if (updatedCount < 0 || updatedCount > messageIds.length) {
        throw new AwikiImError('remote', 'AWiki mark-read acknowledgement is invalid');
      }
    }
    this.unreadMessageIds.delete(key);
    this.groupUnreadMessageIds.delete(key);
    const locallyCleared = localGroupMessageIds.filter((id) => !messageIds.includes(id)).length;
    return updatedCount + locallyCleared;
  }

  /** Resolve and send one idempotent text message. */
  public async sendText(request: SendAwikiTextRequest): Promise<AwikiMessage> {
    return this.exclusiveSend(async () => {
      const text = request.text.trim();
      if (!text) {
        throw new AwikiImError('invalid-request', 'AWiki message text is required');
      }
      const key = sendOperationKey(request.idempotencyKey);
      const fingerprint = sendFingerprint({ kind: 'text', target: request.target, text });
      const existing = this.options.store.snapshot().sendOperations[key];
      if (existing) {
        assertOperationFingerprint(existing.kind, existing.fingerprint, 'text', fingerprint);
        if (existing.kind !== 'text') {
          throw new AwikiImError('conflict', 'AWiki idempotency key is already in use');
        }
        if (existing.stage === 'completed' && existing.result) {
          return structuredClone(existing.result);
        }
        return this.resumeTextSend(key, existing);
      }
      const target = await this.resolveTarget(request.target);
      const stable = stableIdentifiers(request.idempotencyKey);
      const operation: PersistedTextSendOperation = {
        kind: 'text',
        fingerprint,
        target,
        createdAt: new Date().toISOString(),
        operationId: stable.operationId,
        messageId: stable.messageId,
        text,
        stage: 'prepared',
      };
      await this.options.store.mutate((state) => {
        if (state.sendOperations[key]) {
          throw new AwikiImError('conflict', 'AWiki idempotency key is already in use');
        }
        state.sendOperations[key] = operation;
      });
      return this.resumeTextSend(key, operation);
    });
  }

  /** Serialize persistent send state machines across text and attachment operations. */
  public async exclusiveSend<T>(operation: () => Promise<T>): Promise<T> {
    let release: () => void = () => undefined;
    const previous = this.sendTail;
    this.sendTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  /** Resolve a direct Handle/DID or an existing group conversation. */
  public async resolveTarget(target: AwikiMessageTarget): Promise<ResolvedMessageTarget> {
    if (target.kind === 'direct') {
      const peer = target.peer.trim();
      if (!peer) {
        throw new AwikiImError('invalid-request', 'AWiki direct target is required');
      }
      const resolved = peer.startsWith('did:')
        ? { did: peer }
        : await this.resolveHandle(peer.replace(/^wba:\/\//, ''));
      const handle = resolved.handle ?? handleCandidateFromDid(resolved.did);
      const displayName =
        resolved.displayName ??
        (handle
          ? await lookupDisplayName(this.options.transport, handle, resolved.did)
          : undefined);
      const conversationId = directConversationId(resolved.did);
      await this.upsertConversation(
        {
          conversation: directConversation({
            id: conversationId,
            peerDid: resolved.did,
            peerHandle: handle,
            displayName,
          }),
          peerDid: resolved.did,
        },
        true
      );
      return {
        kind: 'direct',
        did: resolved.did,
        ...(handle ? { handle } : {}),
        ...(displayName ? { displayName } : {}),
        conversationId,
      };
    }

    const group = target.group.trim();
    if (!group) {
      throw new AwikiImError('invalid-request', 'AWiki group target is required');
    }
    let record = this.groupConversation(group);
    if (!record) {
      await this.refreshGroups();
      record = this.groupConversation(group);
    }
    if (!record?.groupDid) {
      throw new AwikiImError('not-found', 'AWiki group conversation was not found');
    }
    return {
      kind: 'group',
      did: record.groupDid,
      conversationId: record.conversation.id,
    };
  }

  /** Submit one already-encoded Direct/Group message and persist its projection. */
  public async sendPayload(
    target: ResolvedMessageTarget,
    contentType: string,
    body: Record<string, unknown>,
    wire: { readonly operationId: string; readonly messageId: string; readonly createdAt: string },
    content: AwikiMessageContent,
    attachmentReference?: Omit<PersistedAttachmentReference, 'messageId'>
  ): Promise<AwikiMessage> {
    const identity = this.options.identity.requireSecrets();
    const method = target.kind === 'direct' ? 'direct.send' : 'group.send';
    const meta: Record<string, unknown> = {
      profile: target.kind === 'direct' ? 'anp.direct.base.v1' : 'anp.group.base.v1',
      security_profile: 'transport-protected',
      sender_did: identity.public.did as string,
      target: { kind: target.kind === 'direct' ? 'agent' : 'group', did: target.did },
      operation_id: wire.operationId,
      message_id: wire.messageId,
      created_at: wire.createdAt,
      content_type: contentType,
    };
    const auth = buildOriginAuthentication({
      method,
      meta,
      body,
      signingPrivateKeyPem: identity.signingPrivateKeyPem,
      signingKeyId: identity.signingKeyId,
    });
    const result = await this.authenticatedRpc(method, { meta, auth, body });
    validateSendResult(result, wire, target);
    const messageId = wire.messageId;
    const sentAt = timestampValue(result.accepted_at) ?? Date.now();
    const message: AwikiMessage = {
      id: messageId as AwikiMessageId,
      conversationId: target.conversationId,
      conversationKind: target.kind,
      senderDid: identity.public.did,
      senderHandle: identity.public.handle,
      sentAt,
      outgoing: true,
      content,
    };
    const conversation =
      this.options.store.snapshot().conversations[conversationKey(target.conversationId)];
    await this.options.store.mutate((state) => {
      if (conversation) {
        state.conversations[conversationKey(target.conversationId)] = {
          ...conversation,
          conversation: {
            ...conversation.conversation,
            lastMessageAt: sentAt,
            lastMessagePreview: messagePreview(content),
          },
        };
      }
      if (attachmentReference) {
        const persistedReference = {
          ...attachmentReference,
          messageId,
        };
        state.attachments[attachmentReferenceKey(persistedReference)] = persistedReference;
      }
    });
    return message;
  }

  private async resumeTextSend(
    key: string,
    operation: PersistedTextSendOperation
  ): Promise<AwikiMessage> {
    const message = await this.sendPayload(
      operation.target,
      'text/plain',
      { text: operation.text },
      {
        operationId: operation.operationId,
        messageId: operation.messageId,
        createdAt: operation.createdAt,
      },
      { kind: 'text', text: operation.text }
    );
    await this.options.store.mutate((state) => {
      const current = state.sendOperations[key];
      if (!current || current.kind !== 'text' || current.fingerprint !== operation.fingerprint) {
        throw new AwikiImError('conflict', 'AWiki send operation state changed');
      }
      state.sendOperations[key] = { ...current, stage: 'completed', result: message };
    });
    return message;
  }

  /** Execute a Message Service RPC, refreshing the bearer once on 401/403. */
  public async authenticatedRpc(
    method: string,
    params: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    let identity = this.options.identity.requireSecrets();
    try {
      const result = await this.options.transport.rpc(
        this.options.messageServiceUrl,
        MESSAGE_RPC_PATH,
        method,
        params,
        identity.accessToken
      );
      await this.persistReturnedToken(result.accessToken);
      return result.value;
    } catch (error) {
      const normalized = normalizeAwikiImError(error);
      if (normalized.code !== 'forbidden') {
        throw normalized;
      }
      const accessToken = await this.options.identity.refreshAccessToken();
      identity = this.options.identity.requireSecrets();
      const result = await this.options.transport.rpc(
        this.options.messageServiceUrl,
        MESSAGE_RPC_PATH,
        method,
        params,
        accessToken || identity.accessToken
      );
      await this.persistReturnedToken(result.accessToken);
      return result.value;
    }
  }

  private async refreshConversations(): Promise<void> {
    await this.refreshGroups();
    await this.refreshInbox();
  }

  private async refreshInbox(): Promise<void> {
    const identity = this.options.identity.requireSecrets();
    const unread = new Map<string, string[]>();
    const seen = new Set<string>();
    let skip = 0;
    for (let page = 0; page < MAX_REFRESH_PAGES; page += 1) {
      const result = await this.authenticatedRpc('inbox.get', {
        meta: localMeta(identity.public.did as string, 'anp.inbox.local.v1'),
        body: compactRecord({
          user_did: identity.public.did as string,
          limit: MAX_PAGE_LIMIT,
          skip: skip || undefined,
        }),
      });
      const wires = arrayValue(result.messages);
      const mapped = wires
        .map((wire) =>
          isRecord(wire)
            ? this.mapWireMessage(wire, undefined, identity.public.did as string)
            : null
        )
        .filter((message): message is MappedMessage => message !== null);
      for (const entry of mapped) {
        const message = entry.message;
        if (message.outgoing || seen.has(message.id as string)) continue;
        seen.add(message.id as string);
        const key = conversationKey(message.conversationId);
        unread.set(key, [...(unread.get(key) ?? []), message.id as string]);
      }
      await this.persistMappedMessages(mapped);
      if (result.has_more !== true) {
        this.unreadMessageIds = unread;
        this.inboxRefreshed = true;
        return;
      }
      if (wires.length === 0) {
        throw new AwikiImError('remote', 'AWiki inbox pagination did not advance');
      }
      skip += wires.length;
    }
    throw new AwikiImError('remote', 'AWiki inbox pagination exceeded the safety limit');
  }

  private async refreshGroups(): Promise<void> {
    const identity = this.options.identity.requireSecrets();
    let cursor: string | undefined;
    for (let page = 0; page < MAX_REFRESH_PAGES; page += 1) {
      const result = await this.authenticatedRpc('group.list', {
        meta: groupLocalMeta(identity.public.did as string),
        body: compactRecord({ limit: MAX_PAGE_LIMIT, cursor }),
      });
      const groups = arrayValue(result.groups)
        .map(groupConversationFromWire)
        .filter((group): group is PersistedConversation => group !== null);
      if (groups.length > 0) {
        await this.options.store.mutate((state) => {
          for (const group of groups) {
            state.conversations[conversationKey(group.conversation.id)] = mergeConversation(
              state.conversations[conversationKey(group.conversation.id)],
              group
            );
          }
        });
      }
      const nextCursor = cursorValue(result.next_cursor);
      if (result.has_more === true && !nextCursor) {
        throw new AwikiImError('remote', 'AWiki group pagination omitted its cursor');
      }
      if (!nextCursor) {
        return;
      }
      if (nextCursor === cursor) {
        throw new AwikiImError('remote', 'AWiki group pagination did not advance');
      }
      cursor = nextCursor;
    }
    throw new AwikiImError('remote', 'AWiki group pagination exceeded the safety limit');
  }

  private async resolveHandle(
    peer: string
  ): Promise<{ did: string; handle?: string; displayName?: string }> {
    const result = await this.options.transport.rpc(
      this.options.userServiceUrl,
      HANDLE_RPC_PATH,
      'lookup',
      { handle: peer }
    );
    const did = requiredWireString(result.value.did, 'resolved DID');
    const handle = stringValue(result.value.full_handle) ?? stringValue(result.value.handle);
    const profile = isRecord(result.value.profile) ? result.value.profile : undefined;
    const displayName =
      stringValue(result.value.display_name) ??
      stringValue(profile?.display_name) ??
      (handle ? await lookupDisplayName(this.options.transport, handle, did) : undefined);
    return {
      did,
      ...(handle ? { handle } : {}),
      ...(displayName ? { displayName } : {}),
    };
  }

  /** Fill missing direct `displayName` values from WNS without blocking on failure. */
  private async hydrateDirectDisplayNames(): Promise<void> {
    const pending = Object.values(this.options.store.snapshot().conversations).filter(
      (record) =>
        record.conversation.kind === 'direct' && record.conversation.displayName === undefined
    );
    if (pending.length === 0) {
      return;
    }
    const resolved = await Promise.all(
      pending.map(async (record) => {
        if (record.conversation.kind !== 'direct') {
          return null;
        }
        const handle =
          record.conversation.peerHandle ?? handleCandidateFromDid(record.conversation.peerDid);
        if (!handle) {
          return null;
        }
        const displayName = await lookupDisplayName(
          this.options.transport,
          handle,
          record.conversation.peerDid
        );
        if (!displayName) {
          return null;
        }
        return {
          conversation: directConversation({
            id: record.conversation.id,
            peerDid: record.conversation.peerDid,
            peerHandle: handle,
            displayName,
            lastMessageAt: record.conversation.lastMessageAt,
            lastMessagePreview: record.conversation.lastMessagePreview,
          }),
          peerDid: record.peerDid ?? record.conversation.peerDid,
        };
      })
    );
    const updates = resolved.filter((value): value is NonNullable<typeof value> => value !== null);
    if (updates.length === 0) {
      return;
    }
    await this.options.store.mutate((state) => {
      for (const update of updates) {
        const key = conversationKey(update.conversation.id);
        state.conversations[key] = mergeConversation(state.conversations[key], update);
      }
    });
  }

  /** Refresh Group previews and supplement unread state when Legacy inbox omits Group messages. */
  private async hydrateGroupMessagePreviews(): Promise<void> {
    const identity = this.options.identity.requireSecrets();
    const pending = Object.values(this.options.store.snapshot().conversations).filter(
      (record) => record.conversation.kind === 'group'
    );
    await Promise.all(
      pending.map(async (record) => {
        const key = conversationKey(record.conversation.id);
        const previousWindow = this.groupMessageWindows.get(key);
        const previousLastMessageAt = record.conversation.lastMessageAt;
        const result = await this.authenticatedRpc('group.list_messages', {
          meta: groupLocalMeta(
            identity.public.did as string,
            requiredConversationValue(record.groupDid)
          ),
          body: {
            group_did: requiredConversationValue(record.groupDid),
            limit: MAX_PAGE_LIMIT,
          },
        });
        const wires = arrayValue(result.messages);
        validateHistoryWires(wires, record, identity.public.did as string);
        const mapped = wires
          .map((wire) =>
            isRecord(wire)
              ? this.mapWireMessage(wire, record.conversation, identity.public.did as string)
              : null
          )
          .filter((message): message is MappedMessage => message !== null);
        const currentWindow = new Set(mapped.map((entry) => entry.message.id as string));
        const locallyUnread = new Set(this.groupUnreadMessageIds.get(key) ?? []);
        for (const entry of mapped) {
          const message = entry.message;
          const observedAfterPersistedSummary =
            previousLastMessageAt !== undefined && message.sentAt > previousLastMessageAt;
          const observedAfterEqualTimestamp =
            previousWindow !== undefined &&
            previousLastMessageAt !== undefined &&
            message.sentAt === previousLastMessageAt &&
            !previousWindow.has(message.id as string);
          if (!message.outgoing && (observedAfterPersistedSummary || observedAfterEqualTimestamp)) {
            locallyUnread.add(message.id as string);
          }
        }
        this.groupMessageWindows.set(key, currentWindow);
        if (locallyUnread.size > 0) {
          this.groupUnreadMessageIds.set(key, [...locallyUnread]);
        }
        await this.persistMappedMessages(mapped);
      })
    );
  }

  /** Fill missing incoming group sender names from WNS without blocking history on failure. */
  private async hydrateGroupSenderDisplayNames(
    mapped: readonly MappedMessage[]
  ): Promise<readonly MappedMessage[]> {
    const pending = new Map<string, string>();
    for (const entry of mapped) {
      const message = entry.message;
      if (
        message.conversationKind !== 'group' ||
        message.outgoing ||
        message.senderDisplayName !== undefined
      ) {
        continue;
      }
      const handle = message.senderHandle ?? handleCandidateFromDid(message.senderDid);
      if (handle) {
        pending.set(message.senderDid, handle);
      }
    }
    if (pending.size === 0) {
      return mapped;
    }
    const displayNames = new Map(
      (
        await Promise.all(
          [...pending].map(async ([did, handle]) => {
            const displayName = await lookupDisplayName(this.options.transport, handle, did);
            return displayName ? ([did, displayName] as const) : null;
          })
        )
      ).filter((value): value is readonly [string, string] => value !== null)
    );
    if (displayNames.size === 0) {
      return mapped;
    }
    return mapped.map((entry) => {
      const senderDisplayName = displayNames.get(entry.message.senderDid);
      return senderDisplayName
        ? { ...entry, message: { ...entry.message, senderDisplayName } }
        : entry;
    });
  }

  private mapWireMessage(
    wire: MessageWireValue,
    fallbackConversation: AwikiConversation | undefined,
    ownerDid: string
  ): MappedMessage | null {
    // Group `id` is a local projection (`group_did:event_seq`); message_id is the
    // protocol identity used by attachment authorization and message references.
    const messageId =
      stringValue(wire.message_id) ?? stringValue(wire.id) ?? stringValue(wire.client_msg_id);
    const senderDid = stringValue(wire.sender_did);
    if (!messageId || !senderDid) {
      return null;
    }
    const receiverDid = stringValue(wire.receiver_did);
    const groupDid =
      stringValue(wire.group_did) ??
      (fallbackConversation?.kind === 'group'
        ? (fallbackConversation.groupDid as string)
        : undefined);
    const kind = groupDid ? 'group' : 'direct';
    const peerDid =
      kind === 'direct' ? (senderDid !== ownerDid ? senderDid : receiverDid) : undefined;
    if (kind === 'direct' && !peerDid) {
      return null;
    }
    const conversationId =
      fallbackConversation?.id ??
      (kind === 'group'
        ? groupConversationId(groupDid as string)
        : directConversationId(peerDid as string));
    const sentAt =
      timestampValue(wire.sent_at) ??
      timestampValue(wire.accepted_at) ??
      timestampValue(wire.created_at) ??
      0;
    const contentType = stringValue(wire.content_type) ?? 'text/plain';
    const attachment = parseAttachmentMessage(
      wire.content,
      contentType,
      this.options.attachmentMaxBytes
    );
    const content: AwikiMessageContent = attachment
      ? {
          kind: 'attachment',
          attachment: attachment.attachment,
          ...(attachment.caption ? { caption: attachment.caption } : {}),
        }
      : { kind: 'text', text: textContent(wire) };
    const peerHandle =
      stringValue(wire.peer_full_handle) ??
      (senderDid !== ownerDid ? stringValue(wire.sender_handle) : undefined);
    const senderDisplayName =
      stringValue(wire.sender_display_name) ?? stringValue(wire.display_name);
    const peerDisplayName =
      kind === 'direct'
        ? (stringValue(wire.peer_display_name) ??
          (senderDid !== ownerDid ? senderDisplayName : undefined) ??
          (fallbackConversation?.kind === 'direct' ? fallbackConversation.displayName : undefined))
        : undefined;
    const conversation: AwikiConversation =
      kind === 'group'
        ? {
            kind: 'group',
            id: conversationId,
            groupDid: groupDid as AwikiDid,
            title:
              stringValue(wire.group_name) ??
              (fallbackConversation?.kind === 'group'
                ? fallbackConversation.title
                : (groupDid as string)),
            ...(sentAt ? { lastMessageAt: sentAt } : {}),
            ...(sentAt ? { lastMessagePreview: messagePreview(content) } : {}),
          }
        : directConversation({
            id: conversationId,
            peerDid: peerDid as string,
            peerHandle,
            displayName: peerDisplayName,
            lastMessageAt: sentAt || undefined,
            lastMessagePreview: sentAt ? messagePreview(content) : undefined,
            fallbackTitle:
              fallbackConversation?.kind === 'direct' ? fallbackConversation.title : undefined,
          });
    const message: AwikiMessage = {
      id: messageId as AwikiMessageId,
      conversationId,
      conversationKind: kind,
      senderDid: senderDid as AwikiDid,
      ...(stringValue(wire.sender_handle)
        ? { senderHandle: stringValue(wire.sender_handle) as AwikiHandle }
        : {}),
      ...(senderDisplayName ? { senderDisplayName } : {}),
      sentAt,
      outgoing: senderDid === ownerDid,
      content,
    };
    const attachmentReference = attachment
      ? {
          attachment: attachment.attachment,
          objectUri: attachment.objectUri,
          senderDid,
          messageId,
          ...(kind === 'group' ? { groupDid } : { messageTargetDid: receiverDid ?? peerDid }),
          messageServiceDid: this.options.identity.requireSecrets().messageServiceDid,
        }
      : undefined;
    return {
      message,
      conversation: {
        conversation,
        ...(peerDid ? { peerDid } : {}),
        ...(groupDid ? { groupDid } : {}),
      },
      attachmentReference,
    };
  }

  private async persistMappedMessages(mapped: readonly MappedMessage[]): Promise<void> {
    if (mapped.length === 0) {
      return;
    }
    await this.options.store.mutate((state) => {
      for (const entry of mapped) {
        const key = conversationKey(entry.conversation.conversation.id);
        state.conversations[key] = mergeConversation(state.conversations[key], entry.conversation);
        if (entry.attachmentReference) {
          state.attachments[attachmentReferenceKey(entry.attachmentReference)] =
            entry.attachmentReference;
        }
      }
    });
  }

  private async upsertConversation(
    record: PersistedConversation,
    replaceDirectProfile = false
  ): Promise<void> {
    await this.options.store.mutate((state) => {
      const key = conversationKey(record.conversation.id);
      state.conversations[key] = mergeConversation(
        state.conversations[key],
        record,
        replaceDirectProfile
      );
    });
  }

  private groupConversation(value: string): PersistedConversation | undefined {
    return Object.values(this.options.store.snapshot().conversations).find(
      (record) =>
        record.conversation.kind === 'group' &&
        ((record.conversation.id as string) === value || record.groupDid === value)
    );
  }

  private async persistReturnedToken(token: string | undefined): Promise<void> {
    if (!token || token === this.options.store.snapshot().identity?.accessToken) {
      return;
    }
    await this.options.store.mutate((state) => {
      if (state.identity) {
        state.identity = { ...state.identity, accessToken: token };
      }
    });
  }
}

function validateHistoryWires(
  wires: readonly unknown[],
  conversation: PersistedConversation,
  ownerDid: string
): void {
  for (const wire of wires) {
    if (!isRecord(wire)) {
      throw new AwikiImError('remote', 'AWiki history response contains an invalid message');
    }
    if (conversation.conversation.kind === 'group') {
      if (stringValue(wire.group_did) !== conversation.groupDid) {
        throw new AwikiImError('remote', 'AWiki history message does not belong to the group');
      }
      continue;
    }
    const senderDid = stringValue(wire.sender_did);
    const receiverDid = stringValue(wire.receiver_did);
    const peerDid = conversation.peerDid;
    if (
      !peerDid ||
      !senderDid ||
      !receiverDid ||
      !(
        (senderDid === ownerDid && receiverDid === peerDid) ||
        (senderDid === peerDid && receiverDid === ownerDid)
      )
    ) {
      throw new AwikiImError('remote', 'AWiki history message does not belong to the direct peer');
    }
  }
}

function validateSendResult(
  result: Record<string, unknown>,
  wire: { readonly operationId: string; readonly messageId: string },
  target: ResolvedMessageTarget
): void {
  if (
    result.accepted !== true ||
    result.operation_id !== wire.operationId ||
    result.message_id !== wire.messageId ||
    (target.kind === 'direct' ? result.target_did !== target.did : result.group_did !== target.did)
  ) {
    throw new AwikiImError('remote', 'AWiki send acknowledgement is invalid');
  }
}

interface MappedMessage {
  readonly message: AwikiMessage;
  readonly conversation: PersistedConversation;
  readonly attachmentReference?: PersistedAttachmentReference;
}

function localMeta(senderDid: string, profile: string): Record<string, unknown> {
  return {
    profile,
    security_profile: 'transport-protected',
    sender_did: senderDid,
    operation_id: operationId('op'),
    created_at: new Date().toISOString(),
  };
}

function groupLocalMeta(senderDid: string, groupDid?: string): Record<string, unknown> {
  return {
    profile: 'anp.group.local.v1',
    security_profile: 'transport-protected',
    sender_did: senderDid,
    ...(groupDid ? { target: { kind: 'group', did: groupDid } } : {}),
  };
}

function groupConversationFromWire(value: unknown): PersistedConversation | null {
  if (!isRecord(value)) {
    return null;
  }
  const groupDid = stringValue(value.group_did) ?? stringValue(value.did) ?? stringValue(value.id);
  if (!groupDid) {
    return null;
  }
  const profile = isRecord(value.profile) ? value.profile : undefined;
  const title =
    stringValue(value.title) ??
    stringValue(value.name) ??
    stringValue(value.display_name) ??
    stringValue(profile?.display_name) ??
    groupDid;
  const lastMessageAt = timestampValue(value.last_message_at);
  const lastMessagePreview = stringValue(value.last_message_preview);
  return {
    conversation: {
      kind: 'group',
      id: groupConversationId(groupDid),
      groupDid: groupDid as AwikiDid,
      title,
      ...(lastMessageAt ? { lastMessageAt } : {}),
      ...(lastMessagePreview ? { lastMessagePreview } : {}),
    },
    groupDid,
  };
}

function parseAttachmentMessage(
  rawContent: unknown,
  contentType: string,
  maximumBytes: number
): {
  readonly attachment: AwikiAttachment;
  readonly objectUri: string;
  readonly caption?: string;
} | null {
  if (contentType !== 'application/anp-attachment-manifest+json') {
    return null;
  }
  const decoded =
    typeof rawContent === 'string'
      ? parseJsonRecord(rawContent)
      : isRecord(rawContent)
        ? rawContent
        : undefined;
  if (!decoded) {
    throw new AwikiImError('remote', 'AWiki attachment manifest is invalid');
  }
  const attachments = arrayValue(decoded.attachments);
  if (attachments.length !== 1 || !isRecord(attachments[0])) {
    throw new AwikiImError('remote', 'AWiki attachment manifest is invalid');
  }
  const selected = attachments[0];
  const digest = isRecord(selected.digest) ? selected.digest : undefined;
  const access = isRecord(selected.access_info) ? selected.access_info : undefined;
  const encryption = isRecord(selected.encryption_info) ? selected.encryption_info : undefined;
  const id = stringValue(selected.attachment_id);
  const mimeType = stringValue(selected.mime_type);
  const size = integerValue(selected.size);
  const digestB64u = stringValue(digest?.value_b64u);
  const objectUri = stringValue(access?.object_uri);
  if (
    !id ||
    !mimeType ||
    size === undefined ||
    size > maximumBytes ||
    !digestB64u ||
    !objectUri ||
    digest?.alg !== 'sha-256' ||
    encryption?.mode !== 'none' ||
    (decoded.primary_attachment_id !== undefined && decoded.primary_attachment_id !== id)
  ) {
    throw new AwikiImError('remote', 'AWiki attachment manifest is invalid');
  }
  return {
    attachment: {
      id: id as AwikiAttachmentId,
      fileName: stringValue(selected.filename) ?? id,
      mimeType,
      size,
      sha256: Buffer.from(digestB64u, 'base64url').toString('hex'),
    },
    objectUri,
    ...(stringValue(decoded.caption) ? { caption: stringValue(decoded.caption) } : {}),
  };
}

function textContent(wire: MessageWireValue): string {
  const content = wire.content;
  if (typeof content === 'string') {
    return content;
  }
  if (isRecord(content) && typeof content.text === 'string') {
    return content.text;
  }
  if (isRecord(wire.body) && typeof wire.body.text === 'string') {
    return wire.body.text;
  }
  return '';
}

function messagePreview(content: AwikiMessageContent): string {
  if (content.kind === 'text') {
    return content.text.trim() || '消息';
  }
  const kind = content.attachment.mimeType.startsWith('image/') ? '图片' : '附件';
  return `[${kind}] ${content.attachment.fileName}`;
}

function stableIdentifiers(idempotencyKey: string): {
  readonly operationId: string;
  readonly messageId: string;
} {
  const key = idempotencyKey.trim();
  if (!key || key.length > 256) {
    throw new AwikiImError('invalid-request', 'AWiki idempotency key is invalid');
  }
  const digest = createHash('sha256').update(key).digest('hex').slice(0, 32);
  return { operationId: `op-${digest}`, messageId: `msg-${digest}` };
}

export function sendOperationKey(idempotencyKey: string): string {
  const key = idempotencyKey.trim();
  if (!key || key.length > 256) {
    throw new AwikiImError('invalid-request', 'AWiki idempotency key is invalid');
  }
  return createHash('sha256').update(`send-operation:${key}`).digest('hex');
}

export function sendFingerprint(value: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalizeJson(value)).digest('hex');
}

export function assertOperationFingerprint(
  actualKind: string,
  actualFingerprint: string,
  expectedKind: string,
  expectedFingerprint: string
): void {
  if (actualKind !== expectedKind || actualFingerprint !== expectedFingerprint) {
    throw new AwikiImError('conflict', 'AWiki idempotency key is already in use');
  }
}

function attachmentReferenceKey(reference: PersistedAttachmentReference): string {
  return [reference.senderDid, reference.messageId, reference.attachment.id as string]
    .map((value) => Buffer.from(value).toString('base64url'))
    .join('.');
}

function directConversationId(peerDid: string): AwikiConversationId {
  return `direct:${Buffer.from(peerDid).toString('base64url')}` as AwikiConversationId;
}

function groupConversationId(groupDid: string): AwikiConversationId {
  return `group:${Buffer.from(groupDid).toString('base64url')}` as AwikiConversationId;
}

function mergeConversation(
  current: PersistedConversation | undefined,
  next: PersistedConversation,
  replaceDirectProfile = false
): PersistedConversation {
  if (!current) {
    return next;
  }
  const currentTime = current.conversation.lastMessageAt ?? 0;
  const nextTime = next.conversation.lastMessageAt ?? 0;
  const lastMessageAt = Math.max(currentTime, nextTime);
  const lastMessagePreview =
    nextTime > currentTime
      ? next.conversation.lastMessagePreview
      : currentTime > nextTime
        ? current.conversation.lastMessagePreview
        : (next.conversation.lastMessagePreview ?? current.conversation.lastMessagePreview);
  if (current.conversation.kind === 'direct' && next.conversation.kind === 'direct') {
    const peerHandle = replaceDirectProfile
      ? (next.conversation.peerHandle ?? current.conversation.peerHandle)
      : (current.conversation.peerHandle ?? next.conversation.peerHandle);
    const displayName = replaceDirectProfile
      ? (next.conversation.displayName ?? current.conversation.displayName)
      : (current.conversation.displayName ?? next.conversation.displayName);
    return {
      ...current,
      ...next,
      conversation: directConversation({
        id: next.conversation.id,
        peerDid: next.conversation.peerDid,
        peerHandle,
        displayName,
        lastMessageAt: lastMessageAt || undefined,
        lastMessagePreview,
        fallbackTitle: preferredLabel(
          displayName,
          peerHandle,
          current.conversation.title,
          next.conversation.title,
          next.conversation.peerDid
        ),
      }),
    };
  }
  const { lastMessagePreview: _currentPreview, ...currentConversation } = current.conversation;
  const { lastMessagePreview: _nextPreview, ...nextConversation } = next.conversation;
  void _currentPreview;
  void _nextPreview;
  return {
    ...current,
    ...next,
    conversation: {
      ...currentConversation,
      ...nextConversation,
      ...(lastMessageAt > 0 ? { lastMessageAt } : {}),
      ...(lastMessagePreview !== undefined ? { lastMessagePreview } : {}),
    } as AwikiConversation,
  };
}

function directConversation(args: {
  readonly id: AwikiConversationId;
  readonly peerDid: string;
  readonly peerHandle?: string;
  readonly displayName?: string;
  readonly lastMessageAt?: number;
  readonly lastMessagePreview?: string;
  readonly fallbackTitle?: string;
}): AwikiConversation {
  const title = preferredLabel(args.displayName, args.peerHandle, args.fallbackTitle, args.peerDid);
  return {
    kind: 'direct',
    id: args.id,
    peerDid: args.peerDid as AwikiDid,
    title,
    ...(args.peerHandle ? { peerHandle: args.peerHandle as AwikiHandle } : {}),
    ...(args.displayName ? { displayName: args.displayName } : {}),
    ...(args.lastMessageAt ? { lastMessageAt: args.lastMessageAt } : {}),
    ...(args.lastMessagePreview !== undefined
      ? { lastMessagePreview: args.lastMessagePreview }
      : {}),
  };
}

function preferredLabel(...candidates: readonly (string | undefined)[]): string {
  const values = candidates.filter((value): value is string => !!value && value.trim() !== '');
  return values.find((value) => !value.startsWith('did:')) ?? values[0] ?? '';
}

function compareConversationRecency(left: AwikiConversation, right: AwikiConversation): number {
  return (
    (right.lastMessageAt ?? 0) - (left.lastMessageAt ?? 0) || left.title.localeCompare(right.title)
  );
}

function compareMessageTime(left: AwikiMessage, right: AwikiMessage): number {
  return left.sentAt - right.sentAt || (left.id as string).localeCompare(right.id as string);
}

function pageLimit(value: number | undefined): number {
  if (value === undefined) {
    return DEFAULT_PAGE_LIMIT;
  }
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_PAGE_LIMIT) {
    throw new AwikiImError('invalid-request', 'AWiki page limit is invalid');
  }
  return value;
}

function encodeOffsetCursor(offset: number): AwikiCursor {
  return Buffer.from(JSON.stringify({ v: 1, offset })).toString('base64url') as AwikiCursor;
}

function decodeOffsetCursor(cursor: AwikiCursor | undefined): number {
  if (!cursor) {
    return 0;
  }
  try {
    const decoded: unknown = JSON.parse(
      Buffer.from(cursor as string, 'base64url').toString('utf8')
    );
    if (
      isRecord(decoded) &&
      decoded.v === 1 &&
      typeof decoded.offset === 'number' &&
      Number.isSafeInteger(decoded.offset) &&
      decoded.offset >= 0
    ) {
      return decoded.offset;
    }
  } catch {
    // Invalid opaque cursors share one stable public error below.
  }
  throw new AwikiImError('invalid-request', 'AWiki page cursor is invalid');
}

function encodeHistoryCursor(
  kind: 'direct' | 'group',
  conversationId: AwikiConversationId,
  skip: number
): AwikiCursor {
  return Buffer.from(
    JSON.stringify({ v: 1, kind, conversationId: conversationId as string, skip }),
    'utf8'
  ).toString('base64url') as AwikiCursor;
}

function decodeHistoryCursor(
  cursor: AwikiCursor | undefined,
  expectedKind: 'direct' | 'group',
  expectedConversationId: AwikiConversationId
): number {
  if (!cursor) {
    return 0;
  }
  try {
    const decoded: unknown = JSON.parse(
      Buffer.from(cursor as string, 'base64url').toString('utf8')
    );
    if (
      isRecord(decoded) &&
      decoded.v === 1 &&
      decoded.kind === expectedKind &&
      decoded.conversationId === (expectedConversationId as string) &&
      typeof decoded.skip === 'number' &&
      Number.isSafeInteger(decoded.skip) &&
      decoded.skip >= 0
    ) {
      return decoded.skip;
    }
  } catch {
    // Invalid opaque cursors share one stable public error below.
  }
  throw new AwikiImError('invalid-request', 'AWiki history cursor is invalid');
}

function compactRecord(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

function requiredConversationValue(value: string | undefined): string {
  if (!value) {
    throw new AwikiImError('not-found', 'AWiki conversation was not found');
  }
  return value;
}

function requiredWireString(value: unknown, label: string): string {
  const result = stringValue(value);
  if (!result) {
    throw new AwikiImError('remote', `AWiki response is missing ${label}`);
  }
  return result;
}

function cursorValue(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return stringValue(value);
}

function timestampValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 10_000_000_000 ? value : value * 1000;
  }
  if (typeof value === 'string' && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      return numeric > 10_000_000_000 ? numeric : numeric * 1000;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
}

function integerValue(value: unknown): number | undefined {
  const numeric =
    typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isSafeInteger(numeric) && numeric >= 0 ? numeric : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function arrayValue(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

function parseJsonRecord(value: string): Record<string, unknown> | undefined {
  try {
    const decoded: unknown = JSON.parse(value);
    return isRecord(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
