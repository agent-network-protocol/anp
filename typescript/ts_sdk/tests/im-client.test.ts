import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { createDidWbaDocument } from '../src/authentication/did-wba.js';
import { DidProfile } from '../src/authentication/types.js';
import { createAwikiImClient } from '../src/im/client.js';
import { AwikiImError } from '../src/im/errors.js';
import type {
  AwikiAttachmentId,
  AwikiConversationId,
  AwikiImClient,
  AwikiImClientOptions,
  AwikiMessageId,
} from '../src/im/types.js';

describe('AWiki IM client', () => {
  test('registers one legacy identity and restores it without exposing secrets', async () => {
    const service = new FakeAwikiService();
    const statePath = await temporaryStatePath();
    const client = createClient(service, statePath);

    const otp = await client.sendRegistrationOtp({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
    });
    expect(otp).toEqual({
      retryAfterSeconds: 60,
      retryAt: '2026-08-14T00:01:00Z',
    });
    expect(service.calls[0]).toMatchObject({
      path: '/user-service/v1/handle/rpc',
      method: 'send_otp',
      params: { phone: '+8613800138000' },
    });
    expect(Object.keys(service.calls[0]?.params ?? {})).toEqual(['phone']);

    const identity = await client.registerIdentity({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
      otp: '123456',
    });
    expect(identity.handle).toBe('alice.awiki.test');
    expect(identity.displayName).toBe('Alice');
    expect(identity.did).toMatch(/^did:wba:awiki\.test:alice:e1_/);

    const registration = service.calls.find((call) => call.method === 'register');
    expect(registration?.path).toBe('/user-service/v1/did-auth/rpc');
    expect(registration?.params).toMatchObject({
      handle: 'alice',
      phone: '+8613800138000',
      otp_code: '123456',
    });
    const registeredDocument = registration?.params.did_document as Record<string, unknown>;
    expect(registeredDocument).not.toHaveProperty('deviceManifest');
    expect(registeredDocument).not.toHaveProperty('keyAgreement');
    expect(registeredDocument).not.toHaveProperty('key-2');
    const registeredServices: unknown[] = Array.isArray(registeredDocument.service)
      ? (registeredDocument.service as unknown[])
      : [];
    expect(
      registeredServices.find(
        (service): service is Record<string, unknown> =>
          isUnknownRecord(service) && service.type === 'ANPMessageService'
      )
    ).toMatchObject({
      type: 'ANPMessageService',
      serviceEndpoint: 'https://public-messages.awiki.test/anp-im/rpc',
      serviceDid: 'did:wba:home.awiki.test',
    });

    const persisted = await readFile(statePath, 'utf8');
    expect(persisted).toContain('rootPrivateKeyPem');
    expect(persisted).toContain('test-access-token');
    expect(JSON.stringify(identity)).not.toContain('PRIVATE KEY');
    expect(JSON.stringify(identity)).not.toContain('token');
    expect((await stat(statePath)).mode & 0o777).toBe(0o600);

    await client.dispose();
    const restored = createClient(service, statePath);
    expect(await restored.getIdentity()).toEqual(identity);
    await restored.dispose();
  });

  test('updates, authenticates, and persists the public display name', async () => {
    const service = new FakeAwikiService();
    const statePath = await temporaryStatePath();
    const client = await registeredClient(service, statePath);

    await expect(client.updateDisplayName({ displayName: '  新昵称  ' })).resolves.toMatchObject({
      handle: 'alice.awiki.test',
      displayName: '新昵称',
    });
    const updateCall = service.calls.find((call) => call.method === 'update_me');
    expect(updateCall).toMatchObject({
      path: '/user-service/v1/did/profile/rpc',
      method: 'update_me',
      params: { nick_name: '新昵称' },
    });
    expect(updateCall?.headers.authorization).toBe('Bearer test-access-token');

    service.calls.length = 0;
    service.rpcErrorOnce = { code: 1403 };
    await expect(client.updateDisplayName({ displayName: '刷新后昵称' })).resolves.toMatchObject({
      displayName: '刷新后昵称',
    });
    expect(service.methods()).toEqual(['update_me', 'get_me', 'update_me']);
    expect(service.calls.at(-1)?.headers.authorization).toBe('Bearer refreshed');

    await client.dispose();
    const restored = createClient(service, statePath);
    await expect(restored.getIdentity()).resolves.toMatchObject({ displayName: '刷新后昵称' });
    await restored.dispose();
  });

  test('rejects empty and overlong display names before contacting the service', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);

    await expect(client.updateDisplayName({ displayName: '   ' })).rejects.toMatchObject({
      code: 'invalid-request',
    });
    await expect(client.updateDisplayName({ displayName: '名'.repeat(51) })).rejects.toMatchObject({
      code: 'invalid-request',
    });
    expect(service.calls).toEqual([]);
    await client.dispose();
  });

  test('lists direct and group conversations, pages history, and sends text', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);

    const conversations = await client.listConversations({ limit: 10 });
    expect(conversations.items.map((item) => item.kind)).toEqual(['group', 'direct']);
    const direct = conversations.items.find((item) => item.kind === 'direct');
    const group = conversations.items.find((item) => item.kind === 'group');
    expect(direct).toMatchObject({
      title: 'Bob',
      displayName: 'Bob',
      peerHandle: 'bob.awiki.test',
      unreadCount: 1,
      lastMessagePreview: 'hello from bob',
    });
    expect(group).toMatchObject({
      title: 'Harness Team',
      lastMessagePreview: '[附件] incoming.txt',
    });

    expect(await client.markConversationRead(direct?.id as AwikiConversationId)).toBe(1);
    expect(
      (await client.listConversations()).items.find((item) => item.id === direct?.id)
    ).toMatchObject({ unreadCount: 0 });

    const history = await client.getHistory({
      conversationId: direct?.id as AwikiConversationId,
      limit: 1,
    });
    expect(history.items).toHaveLength(1);
    expect(history.items[0]?.content).toEqual({ kind: 'text', text: 'hello from bob' });
    expect(history.nextCursor).toBeDefined();
    await client.getHistory({
      conversationId: direct?.id as AwikiConversationId,
      cursor: history.nextCursor,
      limit: 1,
    });
    const historyCalls = service.calls.filter((call) => call.method === 'direct.get_history');
    expect(historyCalls[1]?.params.body).toMatchObject({ skip: 1 });
    expect(historyCalls[1]?.params.body).not.toHaveProperty('since_seq');

    const sent = await client.sendText({
      target: { kind: 'group', group: group?.id as string },
      text: 'hello group',
      idempotencyKey: 'send-group-1',
    });
    expect(sent.conversationKind).toBe('group');
    expect(sent.content).toEqual({ kind: 'text', text: 'hello group' });
    const send = service.calls.find((call) => call.method === 'group.send');
    expect(send?.path).toBe('/im/rpc');
    expect(send?.headers.authorization).toBe('Bearer test-access-token');
    expect(send?.params.auth).toMatchObject({ scheme: 'anp-rfc9421-origin-proof-v1' });
    expect(send?.params.meta).toMatchObject({
      profile: 'anp.group.base.v1',
      security_profile: 'transport-protected',
      target: { kind: 'group', did: FakeAwikiService.GROUP_DID },
    });
  });

  test('refreshes group preview, timestamp, and supplemental unread state from group history', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);

    const initial = await client.listConversations();
    const initialGroup = initial.items.find((item) => item.kind === 'group');
    expect(initialGroup).toMatchObject({
      lastMessagePreview: '[附件] incoming.txt',
      unreadCount: 1,
    });
    expect(await client.markConversationRead(initialGroup?.id as AwikiConversationId)).toBe(1);

    service.groupHistoryMessages = [
      {
        id: `${FakeAwikiService.GROUP_DID}:8`,
        message_id: 'group-new-message',
        group_did: FakeAwikiService.GROUP_DID,
        sender_did: FakeAwikiService.BOB_DID,
        content: 'group refresh',
        content_type: 'text/plain',
        sent_at: '2026-08-14T00:04:00Z',
      },
    ];
    const refreshed = await client.listConversations();
    const refreshedGroup = refreshed.items.find((item) => item.kind === 'group');
    expect(refreshedGroup).toMatchObject({
      lastMessageAt: Date.parse('2026-08-14T00:04:00Z'),
      lastMessagePreview: 'group refresh',
      unreadCount: 1,
    });

    expect(await client.markConversationRead(refreshedGroup?.id as AwikiConversationId)).toBe(1);
    const afterRead = await client.listConversations();
    expect(afterRead.items.find((item) => item.id === refreshedGroup?.id)).toMatchObject({
      lastMessageAt: Date.parse('2026-08-14T00:04:00Z'),
      lastMessagePreview: 'group refresh',
      unreadCount: 0,
    });
    expect(service.calls.filter((call) => call.method === 'inbox.mark_read')).toHaveLength(0);
    await client.dispose();
  });

  test('uploads, commits, sends, downloads, and verifies one attachment', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);
    const bytes = new TextEncoder().encode('verified attachment');

    const sent = await client.sendAttachment({
      target: { kind: 'direct', peer: 'bob.awiki.test' },
      attachment: { fileName: 'report.txt', mimeType: 'text/plain', bytes },
      caption: 'report',
      idempotencyKey: 'attachment-1',
    });
    expect(sent.content.kind).toBe('attachment');
    if (sent.content.kind !== 'attachment') throw new Error('attachment expected');
    expect(sent.content.attachment.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(service.methods()).toEqual(
      expect.arrayContaining([
        'attachment.create_slot',
        'PUT',
        'attachment.commit_object',
        'direct.send',
      ])
    );

    const downloaded = await client.downloadAttachment({
      attachmentId: sent.content.attachment.id,
      messageId: sent.id,
    });
    expect(downloaded.bytes).toEqual(bytes);
    expect(service.methods()).toContain('attachment.get_download_ticket');
    expect(service.methods()).toContain('GET');

    service.downloadBytes = new Uint8Array(bytes.byteLength + 1);
    await expect(
      client.downloadAttachment({ attachmentId: sent.content.attachment.id, messageId: sent.id })
    ).rejects.toMatchObject({ name: 'AwikiImError', code: 'remote' });
    const tickets = service.calls.filter(
      (call) => call.method === 'attachment.get_download_ticket'
    );
    expect(tickets).toHaveLength(2);
    expect((tickets[0]?.params.meta as Record<string, unknown>).operation_id).not.toBe(
      (tickets[1]?.params.meta as Record<string, unknown>).operation_id
    );
  });

  test('discovers an incoming attachment sender exact message service', async () => {
    const service = new FakeAwikiService();
    service.includeIncomingAttachment = true;
    const client = await registeredClient(service);
    await client.listConversations();

    const downloaded = await client.downloadAttachment({
      attachmentId: 'att-incoming' as AwikiAttachmentId,
      messageId: 'incoming-attachment-message' as AwikiMessageId,
    });
    expect(new TextDecoder().decode(downloaded.bytes)).toBe('verified attachment');
    const ticket = service.calls.find((call) => call.method === 'attachment.get_download_ticket');
    expect(ticket?.params.meta).toMatchObject({
      target: { kind: 'service', did: 'did:wba:remote-message.awiki.test' },
    });
    expect(service.calls).toContainEqual(
      expect.objectContaining({
        method: 'GET',
        path: `/${FakeAwikiService.BOB_DID.split(':').slice(3).join('/')}/did.json`,
      })
    );
  });

  test('keeps identical attachment IDs distinct across message contexts', async () => {
    const service = new FakeAwikiService();
    service.includeIncomingAttachment = true;
    service.includeDuplicateIncomingAttachment = true;
    const client = await registeredClient(service);
    await client.listConversations();

    await client.downloadAttachment({
      attachmentId: 'att-incoming' as AwikiAttachmentId,
      messageId: 'incoming-attachment-message-2' as AwikiMessageId,
    });
    const ticket = service.calls.find((call) => call.method === 'attachment.get_download_ticket');
    expect(ticket?.params.body).toMatchObject({
      attachment_id: 'att-incoming',
      message_id: 'incoming-attachment-message-2',
    });
  });

  test('uses the protocol message_id rather than a group projection id for attachment tickets', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);
    const conversations = await client.listConversations();
    const group = conversations.items.find((item) => item.kind === 'group');
    const history = await client.getHistory({
      conversationId: group?.id as AwikiConversationId,
      limit: 10,
    });

    expect(history.items[0]?.id).toBe('group-wire-message');
    expect(history.items[0]?.senderDisplayName).toBe('Bob');
    if (history.items[0]?.content.kind !== 'attachment') throw new Error('attachment expected');
    await client.downloadAttachment({
      attachmentId: history.items[0].content.attachment.id,
      messageId: history.items[0].id,
    });
    const ticket = service.calls.find((call) => call.method === 'attachment.get_download_ticket');
    expect(ticket?.params.body).toMatchObject({ message_id: 'group-wire-message' });
  });

  test('normalizes remote errors, validates inputs, and rejects after dispose', async () => {
    const service = new FakeAwikiService();
    const client = createClient(service, await temporaryStatePath());
    service.errorForMethod = 'send_otp';
    await expect(
      client.sendRegistrationOtp({ handle: 'alice.awiki.test', phone: '+8613800138000' })
    ).rejects.toMatchObject({
      name: 'AwikiImError',
      code: 'rate-limited',
      message: 'AWiki request was rate limited',
    });

    await expect(
      client.sendRegistrationOtp({ handle: 'alice.awiki.test', phone: 'invalid' })
    ).rejects.toMatchObject({ code: 'invalid-request' });
    await expect(client.listConversations()).rejects.toMatchObject({ code: 'not-registered' });

    await client.dispose();
    await expect(client.getIdentity()).rejects.toMatchObject({ code: 'remote' });
  });

  test('dispose rejects new work and joins an operation that already entered the client', async () => {
    const service = new FakeAwikiService();
    const client = createClient(service, await temporaryStatePath());
    let markStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    let release: (() => void) | undefined;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    service.waitForMethod = { method: 'send_otp', started: () => markStarted?.(), released };

    const operation = client.sendRegistrationOtp({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
    });
    await started;
    let settled = false;
    const disposal = client.dispose().then(() => {
      settled = true;
    });
    await expect(client.getIdentity()).rejects.toMatchObject({ code: 'remote' });
    await Promise.resolve();
    expect(settled).toBe(false);

    release?.();
    await expect(operation).resolves.toMatchObject({ retryAfterSeconds: 60 });
    await disposal;
    expect(settled).toBe(true);
    await expect(client.dispose()).resolves.toBeUndefined();
  });

  test('rejects unknown attachment downloads without a remote call', async () => {
    const service = new FakeAwikiService();
    const client = await registeredClient(service);
    const callCount = service.calls.length;
    await expect(
      client.downloadAttachment({
        attachmentId: 'missing' as AwikiAttachmentId,
        messageId: 'missing-message' as AwikiMessageId,
      })
    ).rejects.toMatchObject({ code: 'not-found' });
    expect(service.calls).toHaveLength(callCount);
  });

  test('rejects unverified DID documents and attachment origins outside the allowlist', async () => {
    const invalidDidService = new FakeAwikiService();
    invalidDidService.includeIncomingAttachment = true;
    invalidDidService.returnInvalidDidDocument = true;
    const invalidDidClient = await registeredClient(invalidDidService);
    await invalidDidClient.listConversations();
    await expect(
      invalidDidClient.downloadAttachment({
        attachmentId: 'att-incoming' as AwikiAttachmentId,
        messageId: 'incoming-attachment-message' as AwikiMessageId,
      })
    ).rejects.toMatchObject({ code: 'remote' });
    expect(invalidDidService.methods()).not.toContain('attachment.get_download_ticket');

    const blockedObjectService = new FakeAwikiService();
    blockedObjectService.includeIncomingAttachment = true;
    blockedObjectService.incomingObjectUri = 'https://not-allowed.awiki.test/internal/object';
    const blockedObjectClient = await registeredClient(blockedObjectService);
    await blockedObjectClient.listConversations();
    await expect(
      blockedObjectClient.downloadAttachment({
        attachmentId: 'att-incoming' as AwikiAttachmentId,
        messageId: 'incoming-attachment-message' as AwikiMessageId,
      })
    ).rejects.toMatchObject({ code: 'forbidden' });
    expect(blockedObjectService.calls).not.toContainEqual(
      expect.objectContaining({ method: 'GET', path: '/internal/object' })
    );
  });

  test('rejects oversized incoming manifests before DID discovery or ticket requests', async () => {
    const service = new FakeAwikiService();
    service.includeIncomingAttachment = true;
    service.incomingDeclaredSize = 10 * 1024 * 1024 + 1;
    const client = await registeredClient(service);
    await expect(client.listConversations()).rejects.toMatchObject({ code: 'remote' });
    expect(
      service.calls.some((call) => call.method === 'GET' && call.path.includes('/did.json'))
    ).toBe(false);
    expect(service.methods()).not.toContain('attachment.get_download_ticket');
  });

  test('persists text idempotency metadata across response loss and restart', async () => {
    const service = new FakeAwikiService();
    const statePath = await temporaryStatePath();
    const client = createClient(service, statePath);
    await client.sendRegistrationOtp({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
    });
    await client.registerIdentity({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
      otp: '123456',
    });
    service.calls.length = 0;
    const request = {
      target: { kind: 'direct' as const, peer: FakeAwikiService.BOB_DID },
      text: 'persistent hello',
      idempotencyKey: 'persistent-text-1',
    };
    service.loseResponseOnceForMethod = 'direct.send';
    await expect(client.sendText(request)).rejects.toMatchObject({ code: 'network' });
    await client.dispose();

    const restored = createClient(service, statePath);
    const sent = await restored.sendText(request);
    const calls = service.calls.filter((call) => call.method === 'direct.send');
    expect(calls).toHaveLength(2);
    expect(calls[1]?.params.meta).toEqual(calls[0]?.params.meta);
    expect(calls[1]?.params.body).toEqual(calls[0]?.params.body);
    const callCount = service.calls.length;
    expect(await restored.sendText(request)).toEqual(sent);
    expect(service.calls).toHaveLength(callCount);
    await expect(
      restored.sendText({ ...request, text: 'different request' })
    ).rejects.toMatchObject({ code: 'conflict' });
  });

  test('resumes attachment after a lost commit response without re-uploading', async () => {
    const service = new FakeAwikiService();
    const statePath = await temporaryStatePath();
    const client = createClient(service, statePath);
    await client.sendRegistrationOtp({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
    });
    await client.registerIdentity({
      handle: 'alice.awiki.test',
      phone: '+8613800138000',
      otp: '123456',
    });
    service.calls.length = 0;
    const request = {
      target: { kind: 'direct' as const, peer: FakeAwikiService.BOB_DID },
      attachment: {
        fileName: 'resume.txt',
        mimeType: 'text/plain',
        bytes: new TextEncoder().encode('resume attachment'),
      },
      idempotencyKey: 'persistent-attachment-1',
    };
    service.loseResponseOnceForMethod = 'attachment.commit_object';
    await expect(client.sendAttachment(request)).rejects.toMatchObject({ code: 'network' });
    await client.dispose();

    const restored = createClient(service, statePath);
    const sent = await restored.sendAttachment(request);
    expect(service.calls.filter((call) => call.method === 'PUT')).toHaveLength(1);
    const commits = service.calls.filter((call) => call.method === 'attachment.commit_object');
    expect(commits).toHaveLength(2);
    expect(commits[1]?.params).toEqual(commits[0]?.params);
    const callCount = service.calls.length;
    expect(await restored.sendAttachment(request)).toEqual(sent);
    expect(service.calls).toHaveLength(callCount);
    await expect(
      restored.sendAttachment({ ...request, caption: 'different request' })
    ).rejects.toMatchObject({ code: 'conflict' });
  });

  test('rejects missing or cross-bound send acknowledgements for direct and group', async () => {
    const directService = new FakeAwikiService();
    directService.invalidSendAckForMethod = { method: 'direct.send', mode: 'empty' };
    const direct = await registeredClient(directService);
    await expect(
      direct.sendText({
        target: { kind: 'direct', peer: FakeAwikiService.BOB_DID },
        text: 'direct',
        idempotencyKey: 'bad-direct-ack',
      })
    ).rejects.toMatchObject({ code: 'remote' });

    const groupService = new FakeAwikiService();
    groupService.invalidSendAckForMethod = { method: 'group.send', mode: 'wrong' };
    const groupClient = await registeredClient(groupService);
    const group = (await groupClient.listConversations()).items.find(
      (conversation) => conversation.kind === 'group'
    );
    await expect(
      groupClient.sendText({
        target: { kind: 'group', group: group?.id as string },
        text: 'group',
        idempotencyKey: 'bad-group-ack',
      })
    ).rejects.toMatchObject({ code: 'remote' });
  });

  test('rejects cross-conversation direct and group history messages', async () => {
    const directService = new FakeAwikiService();
    directService.directHistoryWrongPeer = true;
    const directClient = await registeredClient(directService);
    const direct = (await directClient.listConversations()).items.find(
      (conversation) => conversation.kind === 'direct'
    );
    await expect(
      directClient.getHistory({ conversationId: direct?.id as AwikiConversationId })
    ).rejects.toMatchObject({ code: 'remote' });

    const groupService = new FakeAwikiService();
    const groupClient = await registeredClient(groupService);
    const group = (await groupClient.listConversations()).items.find(
      (conversation) => conversation.kind === 'group'
    );
    groupService.groupHistoryWrongGroup = true;
    await expect(
      groupClient.getHistory({ conversationId: group?.id as AwikiConversationId })
    ).rejects.toMatchObject({ code: 'remote' });
  });

  test('rejects untrusted slot URLs and commit object URI drift before sending', async () => {
    const slotService = new FakeAwikiService();
    slotService.slotObjectUri = 'https://not-allowed.awiki.test/object';
    const slotClient = await registeredClient(slotService);
    await expect(
      slotClient.sendAttachment({
        target: { kind: 'direct', peer: FakeAwikiService.BOB_DID },
        attachment: {
          fileName: 'blocked.txt',
          mimeType: 'text/plain',
          bytes: new Uint8Array([1]),
        },
        idempotencyKey: 'blocked-slot-origin',
      })
    ).rejects.toMatchObject({ code: 'forbidden' });
    expect(slotService.methods()).not.toContain('PUT');

    const driftService = new FakeAwikiService();
    driftService.commitObjectUri = 'https://objects.awiki.test/objects/different';
    const driftClient = await registeredClient(driftService);
    await expect(
      driftClient.sendAttachment({
        target: { kind: 'direct', peer: FakeAwikiService.BOB_DID },
        attachment: {
          fileName: 'drift.txt',
          mimeType: 'text/plain',
          bytes: new Uint8Array([2]),
        },
        idempotencyKey: 'commit-uri-drift',
      })
    ).rejects.toMatchObject({ code: 'remote' });
    expect(driftService.methods()).not.toContain('direct.send');
  });

  test('validates JSON-RPC envelopes and exact protocol error codes', async () => {
    for (const fault of ['wrong-id', 'missing-version', 'both', 'error-scalar'] as const) {
      const service = new FakeAwikiService();
      service.envelopeFaultOnce = fault;
      const client = createClient(service, await temporaryStatePath());
      await expect(
        client.sendRegistrationOtp({ handle: 'alice.awiki.test', phone: '+8613800138000' })
      ).rejects.toMatchObject({ code: 'remote' });
    }

    const cases = [
      { code: 1003, expected: 'invalid-request' },
      { code: 1403, expected: 'forbidden' },
      { code: 1404, expected: 'not-found' },
      { code: 1409, expected: 'conflict' },
      { code: -32000, serviceCode: 'anp.forbidden', expected: 'forbidden' },
      { code: -32000, serviceCode: 'anp.target_not_found', expected: 'not-found' },
      { code: -32000, serviceCode: 'anp.idempotency_conflict', expected: 'conflict' },
    ] as const;
    for (const value of cases) {
      const service = new FakeAwikiService();
      service.rpcErrorOnce = {
        code: value.code,
        ...('serviceCode' in value ? { serviceCode: value.serviceCode } : {}),
      };
      const client = createClient(service, await temporaryStatePath());
      await expect(
        client.sendRegistrationOtp({ handle: 'alice.awiki.test', phone: '+8613800138000' })
      ).rejects.toMatchObject({ code: value.expected });
    }
  });

  test('resolves a Handle through User Service lookup and rejects a missing peer', async () => {
    const unregistered = createClient(new FakeAwikiService(), await temporaryStatePath());
    await expect(unregistered.resolvePeer('bob.awiki.test')).rejects.toMatchObject({
      code: 'not-registered',
    });
    await unregistered.dispose();

    const service = new FakeAwikiService();
    const client = await registeredClient(service);
    const resolved = await client.resolvePeer('bob.awiki.test');
    expect(resolved).toMatchObject({
      did: FakeAwikiService.BOB_DID,
      handle: 'bob.awiki.test',
      displayName: 'Bob',
    });
    expect(resolved.conversationId).toBeTruthy();
    expect(service.calls.some((call) => call.method === 'lookup')).toBe(true);
    await expect(client.resolvePeer('   ')).rejects.toMatchObject({ code: 'invalid-request' });
    await expect(client.resolvePeer('missing.awiki.test')).rejects.toMatchObject({
      code: 'not-found',
    });
    await client.dispose();
  });

  test('refreshes and persists the latest peer display name when resolving an existing DID', async () => {
    const service = new FakeAwikiService();
    const statePath = await temporaryStatePath();
    const client = await registeredClient(service, statePath);
    await client.resolvePeer('bob.awiki.test');

    service.bobDisplayName = 'Robert';
    service.calls.length = 0;
    const refreshed = await client.resolvePeer(FakeAwikiService.BOB_DID);
    expect(refreshed).toMatchObject({
      did: FakeAwikiService.BOB_DID,
      handle: 'bob.awiki.test',
      displayName: 'Robert',
    });
    expect(
      service.calls.some((call) => call.method === 'GET' && call.path === '/.well-known/handle/bob')
    ).toBe(true);

    await client.getHistory({ conversationId: refreshed.conversationId });
    const afterHistory = await client.listConversations();
    expect(afterHistory.items.find((item) => item.kind === 'direct')).toMatchObject({
      kind: 'direct',
      displayName: 'Robert',
      title: 'Robert',
    });

    const persisted = JSON.parse(await readFile(statePath, 'utf8')) as {
      conversations: Record<string, { conversation: { displayName?: string; title: string } }>;
    };
    expect(
      Object.values(persisted.conversations).some(
        ({ conversation }) =>
          conversation.displayName === 'Robert' && conversation.title === 'Robert'
      )
    ).toBe(true);

    await client.dispose();
    const restored = createClient(service, statePath);
    const restoredConversations = await restored.listConversations();
    expect(restoredConversations.items.find((item) => item.kind === 'direct')).toMatchObject({
      kind: 'direct',
      displayName: 'Robert',
      title: 'Robert',
    });
    await restored.dispose();
  });

  test('titles a handle-less inbox direct chat from the WNS display name', async () => {
    const service = new FakeAwikiService();
    service.omitDirectHandle = true;
    const client = await registeredClient(service);
    const conversations = await client.listConversations();
    const direct = conversations.items.find((item) => item.kind === 'direct');
    expect(direct).toMatchObject({
      kind: 'direct',
      displayName: 'Bob',
      title: 'Bob',
      peerHandle: 'bob.awiki.test',
    });
    expect(direct?.title).not.toMatch(/^did:/);
    const wellKnown = service.calls.filter(
      (call) => call.method === 'GET' && call.path.startsWith('/.well-known/handle/')
    );
    expect(wellKnown).toHaveLength(1);
    service.calls.length = 0;
    await client.listConversations();
    expect(
      service.calls.filter(
        (call) => call.method === 'GET' && call.path.startsWith('/.well-known/handle/')
      )
    ).toHaveLength(0);
    await client.dispose();
  });
});

async function registeredClient(
  service: FakeAwikiService,
  statePath?: string
): Promise<AwikiImClient> {
  const client = createClient(service, statePath ?? (await temporaryStatePath()));
  await client.sendRegistrationOtp({
    handle: 'alice.awiki.test',
    phone: '+8613800138000',
  });
  await client.registerIdentity({
    handle: 'alice.awiki.test',
    phone: '+8613800138000',
    otp: '123456',
  });
  service.calls.length = 0;
  return client;
}

function createClient(service: FakeAwikiService, statePath: string): AwikiImClient {
  const options: AwikiImClientOptions = {
    userServiceUrl: 'https://auth-control.awiki.test',
    userServiceDomain: 'awiki.test',
    messageServiceUrl: 'https://messages.awiki.test',
    messageServicePublicUrl: 'https://public-messages.awiki.test',
    messageServiceDid: 'did:wba:home.awiki.test',
    attachmentMaxBytes: 10 * 1024 * 1024,
    allowedAttachmentOrigins: [
      'https://awiki.test',
      'https://objects.awiki.test',
      'https://public-messages.awiki.test',
      'https://remote-message.awiki.test',
      'https://remote-message-backup.awiki.test',
    ],
    statePath,
    fetch: service.fetch,
  };
  return createAwikiImClient(options);
}

async function temporaryStatePath(): Promise<string> {
  return join(await mkdtemp(join(tmpdir(), 'awiki-im-ts-')), 'identity.json');
}

interface FakeCall {
  readonly path: string;
  readonly method: string;
  readonly params: Record<string, unknown>;
  readonly headers: Record<string, string>;
}

const bobDidBundle = createDidWbaDocument('awiki.test', {
  pathSegments: ['bob'],
  didProfile: DidProfile.E1,
  enableE2ee: false,
  domain: 'awiki.test',
  challenge: 'awiki-im-sdk-test-bob',
  services: [
    {
      id: '#message-backup',
      type: 'ANPMessageService',
      serviceEndpoint: 'https://remote-message-backup.awiki.test/anp-im/rpc',
      serviceDid: 'did:wba:remote-message-backup.awiki.test',
      profiles: ['anp.attachment.v1'],
      securityProfiles: ['transport-protected'],
      priority: 10,
    },
    {
      id: '#message',
      type: 'ANPMessageService',
      serviceEndpoint: 'https://remote-message.awiki.test/anp-im/rpc',
      serviceDid: 'did:wba:remote-message.awiki.test',
      profiles: ['anp.attachment.v1'],
      securityProfiles: ['transport-protected'],
      priority: 1,
    },
  ],
});

class FakeAwikiService {
  public static readonly BOB_DID = bobDidBundle.didDocument.id;
  public static readonly GROUP_DID = 'did:wba:awiki.test:group:harness';
  public readonly calls: FakeCall[] = [];
  public errorForMethod?: string;
  public includeIncomingAttachment = false;
  public includeDuplicateIncomingAttachment = false;
  public returnInvalidDidDocument = false;
  public incomingObjectUri = 'https://objects.awiki.test/objects/object-1';
  public incomingDeclaredSize?: number;
  public downloadBytes = new TextEncoder().encode('verified attachment');
  public loseResponseOnceForMethod?: string;
  public invalidSendAckForMethod?: { readonly method: string; readonly mode: 'empty' | 'wrong' };
  public directHistoryWrongPeer = false;
  public groupHistoryWrongGroup = false;
  public slotUploadUri = 'https://objects.awiki.test/objects/upload/slot-1';
  public slotObjectUri = 'https://objects.awiki.test/objects/object-1';
  public commitObjectUri = 'https://objects.awiki.test/objects/object-1';
  public envelopeFaultOnce?: 'wrong-id' | 'missing-version' | 'both' | 'error-scalar';
  public rpcErrorOnce?: { readonly code: number; readonly serviceCode?: string };
  public omitDirectHandle = false;
  public bobDisplayName = 'Bob';
  public bobMessageDisplayName = 'Bob';
  public groupHistoryMessages?: readonly Record<string, unknown>[];
  private readonly readMessageIds = new Set<string>();
  public waitForMethod?: {
    readonly method: string;
    readonly started: () => void;
    readonly released: Promise<void>;
  };
  private aliceDid = '';

  public readonly fetch = async (
    input: string | URL | Request,
    init?: RequestInit
  ): Promise<Response> => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input : input.url
    );
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => {
      headers[key] = value;
    });
    if (init?.method === 'PUT') {
      this.calls.push({ path: url.pathname, method: 'PUT', params: {}, headers });
      this.downloadBytes = new Uint8Array(await new Response(init.body).arrayBuffer());
      return new Response(null, { status: 204 });
    }
    if (init?.method === 'GET') {
      this.calls.push({ path: url.pathname, method: 'GET', params: {}, headers });
      if (url.pathname.startsWith('/.well-known/handle/')) {
        const local = url.pathname.slice('/.well-known/handle/'.length);
        if (local === 'alice' && this.aliceDid) {
          return Response.json({
            handle: 'alice.awiki.test',
            did: this.aliceDid,
            status: 'active',
            binding_generation: '1',
            profile: {
              type: 'DIDSubjectProfile',
              subject_did: this.aliceDid,
              subject_type: 'person',
              handle: 'alice.awiki.test',
              display_name: 'Alice',
            },
          });
        }
        if (local !== 'bob') {
          return new Response('not found', { status: 404 });
        }
        return Response.json({
          handle: 'bob.awiki.test',
          did: FakeAwikiService.BOB_DID,
          status: 'active',
          binding_generation: '1',
          profile: {
            type: 'DIDSubjectProfile',
            subject_did: FakeAwikiService.BOB_DID,
            subject_type: 'person',
            handle: 'bob.awiki.test',
            display_name: this.bobDisplayName,
          },
        });
      }
      if (url.pathname.endsWith('/did.json')) {
        return Response.json(
          this.returnInvalidDidDocument
            ? { ...bobDidBundle.didDocument, proof: undefined }
            : bobDidBundle.didDocument
        );
      }
      return new Response(this.downloadBytes, { status: 200 });
    }
    const payload = JSON.parse(String(init?.body)) as {
      id: string;
      method: string;
      params: Record<string, unknown>;
    };
    this.calls.push({
      path: url.pathname,
      method: payload.method,
      params: payload.params,
      headers,
    });
    if (this.waitForMethod?.method === payload.method) {
      this.waitForMethod.started();
      await this.waitForMethod.released;
      this.waitForMethod = undefined;
    }
    const response = this.rpcErrorOnce
      ? rpcError(this.rpcErrorOnce.code, 'untrusted remote text', {
          ...(this.rpcErrorOnce.serviceCode ? { anp_code: this.rpcErrorOnce.serviceCode } : {}),
        })
      : this.errorForMethod === payload.method
        ? rpcError(-32005, 'private remote detail: test-access-token', {
            code: 'otp_rate_limited',
          })
        : this.rpc(payload.method, payload.params);
    this.rpcErrorOnce = undefined;
    const decoded = (await response.json()) as Record<string, unknown>;
    if (this.loseResponseOnceForMethod === payload.method) {
      this.loseResponseOnceForMethod = undefined;
      throw new TypeError('simulated response loss');
    }
    const fault = this.envelopeFaultOnce;
    this.envelopeFaultOnce = undefined;
    if (fault === 'wrong-id') return Response.json({ ...decoded, id: 'wrong-id' });
    if (fault === 'missing-version') {
      const { jsonrpc: _jsonrpc, ...withoutVersion } = decoded;
      return Response.json({ ...withoutVersion, id: payload.id });
    }
    if (fault === 'both') {
      return Response.json({ ...decoded, id: payload.id, result: {}, error: { code: 1003 } });
    }
    if (fault === 'error-scalar') {
      return Response.json({ ...decoded, id: payload.id, result: null, error: 'invalid' });
    }
    return Response.json({ ...decoded, id: payload.id });
  };

  public methods(): string[] {
    return this.calls.map((call) => call.method);
  }

  private rpc(method: string, params: Record<string, unknown>): Response {
    switch (method) {
      case 'send_otp':
        return rpcResult({
          ok: true,
          retry_after_seconds: 60,
          retry_at: '2026-08-14T00:01:00Z',
        });
      case 'register': {
        const document = params.did_document as { id: string };
        this.aliceDid = document.id;
        return rpcResult({
          state: 'registered',
          did: document.id,
          user_id: 'user-1',
          message: 'Registration successful',
          access_token: 'test-access-token',
          handle: 'alice',
          domain: 'awiki.test',
          full_handle: 'alice.awiki.test',
          binding_generation: '1',
        });
      }
      case 'update_me':
        return rpcResult({ display_name: String(params.nick_name) });
      case 'lookup': {
        const handle = String(params.handle ?? '').toLowerCase();
        if (handle.includes('missing')) {
          return rpcError(1404, 'handle not found', { anp_code: 'anp.target_not_found' });
        }
        return rpcResult({
          did: FakeAwikiService.BOB_DID,
          handle: 'bob',
          full_handle: 'bob.awiki.test',
        });
      }
      case 'group.list':
        return rpcResult({
          groups: [
            {
              group_did: FakeAwikiService.GROUP_DID,
              display_name: 'Harness Team',
              last_message_at: '2026-08-14T00:02:00Z',
            },
          ],
        });
      case 'inbox.get':
        return rpcResult({
          messages: [
            {
              id: 'inbox-1',
              sender_did: FakeAwikiService.BOB_DID,
              ...(this.omitDirectHandle ? {} : { sender_handle: 'bob.awiki.test' }),
              receiver_did: this.aliceDid,
              content: 'hello from bob',
              content_type: 'text/plain',
              sent_at: '2026-08-14T00:03:00Z',
            },
            ...(this.includeIncomingAttachment
              ? [
                  this.incomingAttachmentMessage('incoming-attachment-message'),
                  ...(this.includeDuplicateIncomingAttachment
                    ? [this.incomingAttachmentMessage('incoming-attachment-message-2')]
                    : []),
                ]
              : []),
          ].filter(
            (message) => typeof message.id !== 'string' || !this.readMessageIds.has(message.id)
          ),
        });
      case 'inbox.mark_read': {
        const body = params.body as { message_ids?: unknown };
        const messageIds = Array.isArray(body.message_ids)
          ? body.message_ids.filter((value): value is string => typeof value === 'string')
          : [];
        for (const messageId of messageIds) this.readMessageIds.add(messageId);
        return rpcResult({ updated_count: messageIds.length });
      }
      case 'direct.get_history':
        return rpcResult({
          messages: [
            {
              id: 'history-1',
              sender_did: FakeAwikiService.BOB_DID,
              sender_display_name: this.bobMessageDisplayName,
              receiver_did: this.directHistoryWrongPeer
                ? 'did:wba:awiki.test:mallory'
                : this.aliceDid,
              content: 'hello from bob',
              content_type: 'text/plain',
              sent_at: '2026-08-14T00:03:00Z',
            },
          ],
          has_more: true,
          next_since_seq: '42',
        });
      case 'group.list_messages':
        return rpcResult({
          messages: this.groupHistoryMessages ?? [
            {
              ...this.incomingAttachmentMessage('group-wire-message'),
              id: `${FakeAwikiService.GROUP_DID}:7`,
              message_id: 'group-wire-message',
              group_did: this.groupHistoryWrongGroup
                ? 'did:wba:awiki.test:group:other'
                : FakeAwikiService.GROUP_DID,
            },
          ],
          has_more: false,
        });
      case 'direct.send':
      case 'group.send': {
        if (this.invalidSendAckForMethod?.method === method) {
          return rpcResult(
            this.invalidSendAckForMethod.mode === 'empty'
              ? {}
              : {
                  accepted: true,
                  message_id: 'wrong-message',
                  operation_id: 'wrong-operation',
                  target_did: 'did:wba:wrong.example',
                  group_did: 'did:wba:wrong.example',
                }
          );
        }
        const meta = params.meta as Record<string, unknown>;
        const target = meta.target as Record<string, unknown>;
        return rpcResult({
          accepted: true,
          message_id: meta.message_id,
          operation_id: meta.operation_id,
          ...(target.kind === 'group' ? { group_did: target.did } : { target_did: target.did }),
          accepted_at: '2026-08-14T00:04:00Z',
        });
      }
      case 'attachment.create_slot': {
        const body = params.body as Record<string, unknown>;
        return rpcResult({
          attachment_id: body.attachment_id,
          slot_id: 'slot-1',
          upload_uri: this.slotUploadUri,
          upload_headers: { 'X-ANP-Upload-Token': 'upload-token' },
          object_uri: this.slotObjectUri,
          commit_token: 'commit-token',
          expires_at: '2026-08-14T00:05:00Z',
        });
      }
      case 'attachment.commit_object': {
        const body = params.body as Record<string, unknown>;
        return rpcResult({
          committed: true,
          attachment_id: body.attachment_id,
          object_uri: this.commitObjectUri,
          committed_at: '2026-08-14T00:05:00Z',
        });
      }
      case 'attachment.abort_object':
        return rpcResult({ aborted: true });
      case 'attachment.get_download_ticket': {
        const body = params.body as Record<string, unknown>;
        return rpcResult({
          download_ticket_b64u: 'download-ticket',
          expires_at: '2026-08-14T00:06:00Z',
          ticket_binding: {
            attachment_id: body.attachment_id,
            object_uri: body.object_uri,
            requester_did: body.requester_did,
            message_id: body.message_id,
            message_security_profile: body.message_security_profile,
            ...(body.group_did
              ? { group_did: body.group_did }
              : { message_target_did: body.message_target_did }),
          },
        });
      }
      case 'get_me':
        return rpcResult({ did: this.aliceDid, access_token: 'refreshed' });
      default:
        return rpcError(-32601, 'method not found');
    }
  }

  private incomingAttachmentMessage(messageId: string): Record<string, unknown> {
    const digest = createHash('sha256').update(this.downloadBytes).digest();
    return {
      id: messageId,
      sender_did: FakeAwikiService.BOB_DID,
      receiver_did: this.aliceDid,
      content_type: 'application/anp-attachment-manifest+json',
      content: {
        attachments: [
          {
            attachment_id: 'att-incoming',
            filename: 'incoming.txt',
            mime_type: 'text/plain',
            size: String(this.incomingDeclaredSize ?? this.downloadBytes.byteLength),
            digest: { alg: 'sha-256', value_b64u: digest.toString('base64url') },
            access_info: { object_uri: this.incomingObjectUri },
            encryption_info: { mode: 'none' },
          },
        ],
        primary_attachment_id: 'att-incoming',
      },
      sent_at: '2026-08-14T00:03:30Z',
    };
  }
}

function rpcResult(result: Record<string, unknown>): Response {
  return Response.json({ jsonrpc: '2.0', id: 'test', result, error: null });
}

function rpcError(code: number, message: string, data?: Record<string, unknown>): Response {
  return Response.json({
    jsonrpc: '2.0',
    id: 'test',
    result: null,
    error: { code, message, data },
  });
}

function isUnknownRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

void AwikiImError;
