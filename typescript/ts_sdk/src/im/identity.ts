import { buildAnpMessageService, createDidWbaDocument } from '../authentication/did-wba.js';
import { DidProfile, type ServiceRecord } from '../authentication/types.js';
import {
  generateW3cProof,
  CRYPTOSUITE_EDDSA_JCS_2022,
  PROOF_TYPE_DATA_INTEGRITY,
} from '../proof/proof.js';
import { validateLocalPart } from '../wns/validator.js';
import { AwikiImError, normalizeAwikiImError } from './errors.js';
import { type PendingRegistrationState, type PersistedIdentitySecrets } from './internal.js';
import {
  DID_AUTH_RPC_PATH,
  DID_PROFILE_RPC_PATH,
  HANDLE_RPC_PATH,
  randomChallenge,
  type AwikiImTransport,
} from './protocol.js';
import { lookupDisplayName } from './display-name.js';
import type { AwikiImStateStore } from './storage.js';
import type {
  AwikiDid,
  AwikiHandle,
  AwikiIdentity,
  RegisterIdentityRequest,
  SendRegistrationOtpRequest,
  SendRegistrationOtpResult,
} from './types.js';

interface IdentityRuntimeOptions {
  readonly userServiceUrl: string;
  readonly userServiceDomain: string;
  readonly messageServicePublicUrl: string;
  readonly messageServiceDid: string;
  readonly transport: AwikiImTransport;
  readonly store: AwikiImStateStore;
}

/** Identity registration and token refresh operations for the high-level client. */
export class AwikiIdentityRuntime {
  private registrationTail: Promise<void> = Promise.resolve();
  private profileTail: Promise<void> = Promise.resolve();
  private displayNameResolved = false;

  public constructor(private readonly options: IdentityRuntimeOptions) {}

  /** Return the public identity projection. */
  public getIdentity(): AwikiIdentity | null {
    return this.options.store.snapshot().identity?.public ?? null;
  }

  /** Fill a missing WNS display name once; failures leave the identity unchanged. */
  public async hydrateDisplayName(): Promise<void> {
    const current = this.getIdentity();
    if (!current || current.displayName !== undefined || this.displayNameResolved) {
      return;
    }
    this.displayNameResolved = true;
    const displayName = await lookupDisplayName(
      this.options.transport,
      current.handle,
      current.did
    );
    if (!displayName) {
      return;
    }
    await this.options.store.mutate((state) => {
      if (state.identity) {
        state.identity = {
          ...state.identity,
          public: { ...state.identity.public, displayName },
        };
      }
    });
  }

  /** Reject persisted identity material that belongs to a different configured deployment. */
  public validateConfiguredIdentity(): void {
    const snapshot = this.options.store.snapshot();
    const material = snapshot.identity ?? snapshot.pendingRegistration;
    if (material && material.messageServiceDid !== this.options.messageServiceDid) {
      throw new AwikiImError('conflict', 'AWiki state belongs to a different Message Service');
    }
    const handle = snapshot.identity?.public.handle ?? snapshot.pendingRegistration?.handle;
    if (handle && !handle.endsWith(`.${this.options.userServiceDomain}`)) {
      throw new AwikiImError('conflict', 'AWiki state belongs to a different User Service domain');
    }
  }

  /** Send the phone-only registration OTP supported by the frozen MVP API. */
  public async sendRegistrationOtp(
    request: SendRegistrationOtpRequest
  ): Promise<SendRegistrationOtpResult> {
    if (this.getIdentity()) {
      throw new AwikiImError('already-registered', 'AWiki identity is already registered');
    }
    const phone = normalizePhone(request.phone);
    const handle = normalizeRegistrationHandle(request.handle, this.options.userServiceDomain);
    const result = await this.options.transport.rpc(
      this.options.userServiceUrl,
      HANDLE_RPC_PATH,
      'send_otp',
      { phone }
    );
    const retryAfterSeconds = requiredWireNumber(
      result.value.retry_after_seconds,
      'retry_after_seconds'
    );
    const retryAt = requiredWireString(result.value.retry_at, 'retry_at');
    const registrationOtp = {
      handle: handle.full,
      phone,
      retryAt,
    };
    await this.options.store.mutate((state) => {
      state.registrationOtp = registrationOtp;
    });
    return { retryAfterSeconds, retryAt };
  }

  /** Register and persist the one deployment identity. */
  public async registerIdentity(request: RegisterIdentityRequest): Promise<AwikiIdentity> {
    return this.exclusiveRegistration(async () => {
      if (this.getIdentity()) {
        throw new AwikiImError('already-registered', 'AWiki identity is already registered');
      }
      const registrationOtp = this.options.store.snapshot().registrationOtp;
      const phone = normalizePhone(request.phone);
      const otp = normalizeOtp(request.otp);
      const handle = normalizeRegistrationHandle(request.handle, this.options.userServiceDomain);
      if (
        !registrationOtp ||
        registrationOtp.phone !== phone ||
        registrationOtp.handle !== handle.full
      ) {
        throw new AwikiImError('invalid-request', 'AWiki registration OTP target does not match');
      }
      let pending = this.options.store.snapshot().pendingRegistration;
      if (pending) {
        if (pending.handle !== handle.full || pending.phone !== phone) {
          throw new AwikiImError('conflict', 'AWiki registration is already pending');
        }
        pending = refreshPendingProof(pending, handle.domain);
      } else {
        pending = createPendingRegistration(
          phone,
          handle,
          this.options.messageServicePublicUrl,
          this.options.messageServiceDid
        );
      }
      await this.options.store.mutate((state) => {
        state.pendingRegistration = pending;
      });

      try {
        const result = await this.options.transport.rpc(
          this.options.userServiceUrl,
          DID_AUTH_RPC_PATH,
          'register',
          {
            did_document: pending.didDocument as unknown as Record<string, unknown>,
            handle: handle.local,
            phone,
            otp_code: otp,
          }
        );
        return this.commitRegistration(pending, result.value, result.accessToken);
      } catch (error) {
        const normalized = normalizeAwikiImError(error);
        if (normalized.code === 'conflict') {
          const reconciled = await this.tryReconcilePending(pending);
          if (reconciled) {
            return reconciled;
          }
        }
        throw normalized;
      }
    });
  }

  /** Update the public WNS display name and keep the local projection in sync. */
  public async updateDisplayName(value: string): Promise<AwikiIdentity> {
    return this.exclusiveProfileUpdate(async () => {
      const displayName = value.trim();
      const length = [...displayName].length;
      if (length === 0 || length > 50) {
        throw new AwikiImError(
          'invalid-request',
          'AWiki display name must contain between 1 and 50 characters'
        );
      }
      let identity = this.requireSecrets();
      let result;
      try {
        result = await this.options.transport.rpc(
          this.options.userServiceUrl,
          DID_PROFILE_RPC_PATH,
          'update_me',
          { nick_name: displayName },
          identity.accessToken
        );
      } catch (error) {
        const normalized = normalizeAwikiImError(error);
        if (normalized.code !== 'forbidden') throw normalized;
        const accessToken = await this.refreshAccessToken();
        identity = this.requireSecrets();
        result = await this.options.transport.rpc(
          this.options.userServiceUrl,
          DID_PROFILE_RPC_PATH,
          'update_me',
          { nick_name: displayName },
          accessToken
        );
      }
      const returnedName = requiredWireString(result.value.display_name, 'display_name');
      if (returnedName !== displayName) {
        throw new AwikiImError('remote', 'AWiki service returned an invalid response');
      }
      await this.options.store.mutate((state) => {
        if (state.identity) {
          state.identity = {
            ...state.identity,
            ...(result.accessToken === undefined ? {} : { accessToken: result.accessToken }),
            public: { ...state.identity.public, displayName: returnedName },
          };
        }
      });
      this.displayNameResolved = true;
      return this.getIdentity() ?? identity.public;
    });
  }

  /** Require secret identity material for a message operation. */
  public requireSecrets(): PersistedIdentitySecrets {
    const identity = this.options.store.snapshot().identity;
    if (!identity) {
      throw new AwikiImError('not-registered', 'AWiki identity is not registered');
    }
    return identity;
  }

  /** Refresh an expired bearer by authenticating the persisted DID. */
  public async refreshAccessToken(): Promise<string> {
    const identity = this.requireSecrets();
    const result = await this.options.transport.signedRpc(
      this.options.userServiceUrl,
      DID_AUTH_RPC_PATH,
      'get_me',
      {},
      {
        didDocument: identity.didDocument,
        signingPrivateKeyPem: identity.signingPrivateKeyPem,
        signingKeyId: identity.signingKeyId,
      }
    );
    const token =
      result.accessToken ?? requiredWireString(result.value.access_token, 'access token');
    await this.options.store.mutate((state) => {
      if (state.identity) {
        state.identity = { ...state.identity, accessToken: token };
      }
    });
    return token;
  }

  private async commitRegistration(
    pending: PendingRegistrationState,
    result: Record<string, unknown>,
    headerToken?: string
  ): Promise<AwikiIdentity> {
    const state = requiredWireString(result.state, 'registration state');
    if (state === 'join_required') {
      throw new AwikiImError('already-registered', 'AWiki identity is already registered');
    }
    if (state !== 'registered') {
      throw new AwikiImError('remote', 'AWiki service returned an invalid response');
    }
    const did = requiredWireString(result.did, 'registered DID');
    if (did !== pending.didDocument.id) {
      throw new AwikiImError('remote', 'AWiki service returned an invalid response');
    }
    const fullHandle = stringValue(result.full_handle) ?? pending.handle;
    if (fullHandle !== pending.handle) {
      throw new AwikiImError('remote', 'AWiki service returned an invalid response');
    }
    const accessToken = headerToken ?? requiredWireString(result.access_token, 'access token');
    return this.persistRegisteredIdentity(pending, did, fullHandle, accessToken);
  }

  private async tryReconcilePending(
    pending: PendingRegistrationState
  ): Promise<AwikiIdentity | null> {
    try {
      const result = await this.options.transport.signedRpc(
        this.options.userServiceUrl,
        DID_AUTH_RPC_PATH,
        'get_me',
        {},
        {
          didDocument: pending.didDocument,
          signingPrivateKeyPem: pending.signingPrivateKeyPem,
          signingKeyId: pending.signingKeyId,
        }
      );
      const did = requiredWireString(result.value.did, 'registered DID');
      if (did !== pending.didDocument.id) {
        return null;
      }
      const token =
        result.accessToken ?? requiredWireString(result.value.access_token, 'access token');
      return this.persistRegisteredIdentity(pending, did, pending.handle, token);
    } catch {
      return null;
    }
  }

  private async persistRegisteredIdentity(
    pending: PendingRegistrationState,
    did: string,
    handle: string,
    accessToken: string
  ): Promise<AwikiIdentity> {
    const publicIdentity: AwikiIdentity = {
      did: did as AwikiDid,
      handle: handle as AwikiHandle,
      registeredAt: Date.now(),
    };
    await this.options.store.mutate((state) => {
      state.identity = {
        public: publicIdentity,
        didDocument: pending.didDocument,
        rootPrivateKeyPem: pending.rootPrivateKeyPem,
        signingPrivateKeyPem: pending.signingPrivateKeyPem,
        signingKeyId: pending.signingKeyId,
        accessToken,
        messageServiceDid: pending.messageServiceDid,
      };
      delete state.registrationOtp;
      delete state.pendingRegistration;
    });
    await this.hydrateDisplayName();
    return this.getIdentity() ?? publicIdentity;
  }

  private async exclusiveRegistration<T>(operation: () => Promise<T>): Promise<T> {
    let release: () => void = () => undefined;
    const previous = this.registrationTail;
    this.registrationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async exclusiveProfileUpdate<T>(operation: () => Promise<T>): Promise<T> {
    let release: () => void = () => undefined;
    const previous = this.profileTail;
    this.profileTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function createPendingRegistration(
  phone: string,
  handle: { readonly local: string; readonly domain: string; readonly full: string },
  messageServicePublicUrl: string,
  messageServiceDid: string
): PendingRegistrationState {
  const messageEndpoint = new URL('/anp-im/rpc', messageServicePublicUrl).toString();
  const services: ServiceRecord[] = [
    buildAnpMessageService('#message', messageEndpoint, {
      serviceDid: messageServiceDid,
      profiles: [
        'anp.core.binding.v1',
        'anp.direct.base.v1',
        'anp.group.base.v1',
        'anp.attachment.v1',
      ],
      securityProfiles: ['transport-protected'],
    }),
    {
      id: '#handle',
      type: 'ANPHandleService',
      serviceEndpoint: `https://${handle.domain}/.well-known/handle/${handle.local}`,
    },
  ];
  const bundle = createDidWbaDocument(handle.domain, {
    pathSegments: [handle.local],
    services,
    domain: handle.domain,
    challenge: randomChallenge(),
    didProfile: DidProfile.E1,
    enableE2ee: false,
  });
  const signingKey = bundle.keys['key-1'];
  if (!signingKey) {
    throw new AwikiImError('remote', 'AWiki identity generation failed');
  }
  return {
    handle: handle.full,
    phone,
    didDocument: bundle.didDocument,
    rootPrivateKeyPem: signingKey.privateKeyPem,
    signingPrivateKeyPem: signingKey.privateKeyPem,
    signingKeyId: `${bundle.didDocument.id}#key-1`,
    messageServiceDid,
  };
}

function refreshPendingProof(
  pending: PendingRegistrationState,
  domain: string
): PendingRegistrationState {
  const unsigned = structuredClone(pending.didDocument);
  delete unsigned.proof;
  const didDocument = generateW3cProof(
    unsigned,
    pending.rootPrivateKeyPem,
    `${unsigned.id}#key-1`,
    {
      proofPurpose: 'assertionMethod',
      proofType: PROOF_TYPE_DATA_INTEGRITY,
      cryptosuite: CRYPTOSUITE_EDDSA_JCS_2022,
      domain,
      challenge: randomChallenge(),
    }
  );
  return { ...pending, didDocument };
}

function normalizeRegistrationHandle(
  input: string,
  userServiceDomain: string
): { readonly local: string; readonly domain: string; readonly full: string } {
  const value = input
    .trim()
    .toLowerCase()
    .replace(/^wba:\/\//, '');
  const configuredDomain = userServiceDomain.toLowerCase();
  const dot = value.indexOf('.');
  const local = dot < 0 ? value : value.slice(0, dot);
  const domain = dot < 0 ? configuredDomain : value.slice(dot + 1);
  if (!validateLocalPart(local) || !domain.includes('.') || domain !== configuredDomain) {
    throw new AwikiImError('invalid-request', 'AWiki handle is invalid');
  }
  return { local, domain, full: `${local}.${domain}` };
}

function normalizePhone(value: string): string {
  const phone = value.trim().replace(/[\s()-]/g, '');
  if (!/^\+?[0-9]{6,20}$/.test(phone)) {
    throw new AwikiImError('invalid-request', 'AWiki phone number is invalid');
  }
  return phone;
}

function normalizeOtp(value: string): string {
  const otp = value.trim();
  if (!/^[0-9]{4,12}$/.test(otp)) {
    throw new AwikiImError('invalid-otp', 'AWiki verification code is invalid');
  }
  return otp;
}

function requiredWireString(value: unknown, label: string): string {
  const result = stringValue(value);
  if (!result) {
    throw new AwikiImError('remote', `AWiki response is missing ${label}`);
  }
  return result;
}

function requiredWireNumber(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new AwikiImError('remote', `AWiki response is missing ${label}`);
  }
  return value;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
