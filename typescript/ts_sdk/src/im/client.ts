import { AwikiAttachmentRuntime } from './attachments.js';
import { normalizeAwikiImError, AwikiImError } from './errors.js';
import { AwikiIdentityRuntime } from './identity.js';
import { AwikiMessagingRuntime } from './messaging.js';
import { AwikiImTransport, validateServiceBaseUrl } from './protocol.js';
import { AwikiImStateStore } from './storage.js';
import type {
  AwikiDid,
  AwikiHandle,
  AwikiIdentity,
  AwikiImClient,
  AwikiResolvedPeer,
  AwikiImClientOptions,
  AwikiPageRequest,
  AwikiPage,
  AwikiConversation,
  AwikiConversationId,
  GetAwikiHistoryRequest,
  AwikiMessage,
  SendAwikiTextRequest,
  SendAwikiAttachmentRequest,
  DownloadAwikiAttachmentRequest,
  DownloadedAwikiAttachment,
  RegisterIdentityRequest,
  SendRegistrationOtpRequest,
  SendRegistrationOtpResult,
  UpdateAwikiDisplayNameRequest,
} from './types.js';

/** Create one high-level Node.js AWiki IM client. */
export function createAwikiImClient(options: AwikiImClientOptions): AwikiImClient {
  return new DefaultAwikiImClient(options);
}

class DefaultAwikiImClient implements AwikiImClient {
  private readonly store: AwikiImStateStore;
  private readonly transport: AwikiImTransport;
  private readonly identity: AwikiIdentityRuntime;
  private readonly messaging: AwikiMessagingRuntime;
  private readonly attachments: AwikiAttachmentRuntime;
  private readonly ready: Promise<void>;
  private readonly inFlight = new Set<Promise<unknown>>();
  private disposal: Promise<void> | undefined;
  private disposed = false;

  public constructor(options: AwikiImClientOptions) {
    const allowInsecureLoopback = options.allowInsecureLoopbackForTesting === true;
    validateServiceBaseUrl(options.userServiceUrl, allowInsecureLoopback);
    validateServiceBaseUrl(options.messageServiceUrl, allowInsecureLoopback);
    validateServiceBaseUrl(options.messageServicePublicUrl, allowInsecureLoopback);
    if (!isDomainName(options.userServiceDomain)) {
      throw new AwikiImError('invalid-request', 'AWiki userServiceDomain is invalid');
    }
    if (!isBareDomainDidWba(options.messageServiceDid)) {
      throw new AwikiImError('invalid-request', 'AWiki messageServiceDid is invalid');
    }
    if (
      !Array.isArray(options.allowedAttachmentOrigins) ||
      options.allowedAttachmentOrigins.length === 0
    ) {
      throw new AwikiImError('invalid-request', 'AWiki allowedAttachmentOrigins is required');
    }
    if (!Number.isSafeInteger(options.attachmentMaxBytes) || options.attachmentMaxBytes < 1) {
      throw new AwikiImError('invalid-request', 'AWiki attachmentMaxBytes is invalid');
    }
    if (!options.statePath.trim()) {
      throw new AwikiImError('invalid-request', 'AWiki statePath is required');
    }
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      throw new AwikiImError('invalid-request', 'AWiki fetch implementation is required');
    }
    this.store = new AwikiImStateStore(options.statePath);
    this.transport = new AwikiImTransport(fetchImpl, {
      allowedAttachmentOrigins: options.allowedAttachmentOrigins,
      allowInsecureLoopback,
      attachmentMaxBytes: options.attachmentMaxBytes,
    });
    this.identity = new AwikiIdentityRuntime({
      userServiceUrl: options.userServiceUrl,
      userServiceDomain: options.userServiceDomain.toLowerCase(),
      messageServicePublicUrl: options.messageServicePublicUrl,
      messageServiceDid: options.messageServiceDid,
      transport: this.transport,
      store: this.store,
    });
    this.messaging = new AwikiMessagingRuntime({
      userServiceUrl: options.userServiceUrl,
      messageServiceUrl: options.messageServiceUrl,
      transport: this.transport,
      store: this.store,
      identity: this.identity,
      attachmentMaxBytes: options.attachmentMaxBytes,
    });
    this.attachments = new AwikiAttachmentRuntime({
      transport: this.transport,
      store: this.store,
      identity: this.identity,
      messaging: this.messaging,
      attachmentMaxBytes: options.attachmentMaxBytes,
    });
    this.ready = this.store.load().then(() => this.identity.validateConfiguredIdentity());
  }

  public async getIdentity(): Promise<AwikiIdentity | null> {
    return this.run(async () => {
      await this.identity.hydrateDisplayName();
      return structuredClone(this.identity.getIdentity());
    });
  }

  public async sendRegistrationOtp(
    request: SendRegistrationOtpRequest
  ): Promise<SendRegistrationOtpResult> {
    return this.run(() => this.identity.sendRegistrationOtp(request));
  }

  public async registerIdentity(request: RegisterIdentityRequest): Promise<AwikiIdentity> {
    return this.run(() => this.identity.registerIdentity(request));
  }

  public async updateDisplayName(request: UpdateAwikiDisplayNameRequest): Promise<AwikiIdentity> {
    return this.run(() => this.identity.updateDisplayName(request.displayName));
  }

  public async resolvePeer(peer: string): Promise<AwikiResolvedPeer> {
    return this.run(async () => {
      this.identity.requireSecrets();
      const resolved = await this.messaging.resolveTarget({ kind: 'direct', peer });
      return {
        did: resolved.did as AwikiDid,
        conversationId: resolved.conversationId,
        ...(resolved.handle === undefined ? {} : { handle: resolved.handle as AwikiHandle }),
        ...(resolved.displayName === undefined ? {} : { displayName: resolved.displayName }),
      };
    });
  }

  public async listConversations(
    request?: AwikiPageRequest
  ): Promise<AwikiPage<AwikiConversation>> {
    return this.run(() => this.messaging.listConversations(request));
  }

  public async getHistory(request: GetAwikiHistoryRequest): Promise<AwikiPage<AwikiMessage>> {
    return this.run(() => this.messaging.getHistory(request));
  }

  public async markConversationRead(conversationId: AwikiConversationId): Promise<number> {
    return this.run(() => this.messaging.markConversationRead(conversationId));
  }

  public async sendText(request: SendAwikiTextRequest): Promise<AwikiMessage> {
    return this.run(() => this.messaging.sendText(request));
  }

  public async sendAttachment(request: SendAwikiAttachmentRequest): Promise<AwikiMessage> {
    return this.run(() => this.attachments.sendAttachment(request));
  }

  public async downloadAttachment(
    request: DownloadAwikiAttachmentRequest
  ): Promise<DownloadedAwikiAttachment> {
    return this.run(() => this.attachments.downloadAttachment(request));
  }

  public async dispose(): Promise<void> {
    this.disposal ??= this.disposeOnce();
    return this.disposal;
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.disposed) {
      return Promise.reject(new AwikiImError('remote', 'AWiki IM client has been disposed'));
    }
    const pending = (async () => {
      try {
        await this.ready;
        return await operation();
      } catch (error) {
        throw normalizeAwikiImError(error);
      }
    })();
    this.inFlight.add(pending);
    void pending.then(
      () => this.inFlight.delete(pending),
      () => this.inFlight.delete(pending)
    );
    return pending;
  }

  private async disposeOnce(): Promise<void> {
    this.disposed = true;
    this.transport.dispose();
    const ready = this.ready.catch((error: unknown) => {
      throw normalizeAwikiImError(error);
    });
    await Promise.allSettled([...this.inFlight]);
    await ready;
  }
}

function isDomainName(value: string): boolean {
  const domain = value.trim().toLowerCase();
  if (!domain || domain.length > 253 || domain.includes('/') || domain.includes(':')) {
    return false;
  }
  try {
    return new URL(`https://${domain}`).hostname === domain;
  } catch {
    return false;
  }
}

function isBareDomainDidWba(value: string): boolean {
  const prefix = 'did:wba:';
  const normalized = value.trim().toLowerCase();
  return normalized.startsWith(prefix) && isDomainName(normalized.slice(prefix.length));
}
