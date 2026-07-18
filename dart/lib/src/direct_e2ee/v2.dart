import 'dart:convert';

import '../authentication/device_manifest.dart';
import '../authentication/types.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';
import '../proof/object_proof.dart';

const String directE2eeProfileV2 = 'anp.direct.e2ee.v2';
const String directE2eeSecurityProfile = 'direct-e2ee';
const String transportProtectedSecurityProfile = 'transport-protected';
const String contentTypeDirectInitV2 = 'application/anp-direct-init+json';
const String contentTypeDirectCipherV2 = 'application/anp-direct-cipher+json';
const String mtiDirectE2eeSuiteV2 =
    'ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1';

class AnpDirectE2eeV2Exception extends AnpException {
  const AnpDirectE2eeV2Exception(super.message, {super.cause});
}

class DirectE2eeV2ProtocolError {
  const DirectE2eeV2ProtocolError(this.code, this.anpCode);

  final int code;
  final String anpCode;
}

const List<DirectE2eeV2ProtocolError> directE2eeV2Errors = [
  DirectE2eeV2ProtocolError(4000, 'anp.direct.e2ee.bundle_not_found'),
  DirectE2eeV2ProtocolError(4001, 'anp.direct.e2ee.bundle_invalid'),
  DirectE2eeV2ProtocolError(4002, 'anp.direct.e2ee.bundle_expired'),
  DirectE2eeV2ProtocolError(4003, 'anp.direct.e2ee.opk_unavailable'),
  DirectE2eeV2ProtocolError(4004, 'anp.direct.e2ee.missing_key_agreement'),
  DirectE2eeV2ProtocolError(4005, 'anp.direct.e2ee.session_not_found'),
  DirectE2eeV2ProtocolError(4006, 'anp.direct.e2ee.session_conflict'),
  DirectE2eeV2ProtocolError(4007, 'anp.direct.e2ee.bad_init_message'),
  DirectE2eeV2ProtocolError(4008, 'anp.direct.e2ee.replay_detected'),
  DirectE2eeV2ProtocolError(4009, 'anp.direct.e2ee.decrypt_failed'),
  DirectE2eeV2ProtocolError(4010, 'anp.direct.e2ee.max_skip_exceeded'),
  DirectE2eeV2ProtocolError(4011, 'anp.direct.e2ee.reset_required'),
  DirectE2eeV2ProtocolError(4012, 'anp.direct.e2ee.invalid_security_binding'),
];

DirectE2eeV2ProtocolError? directE2eeV2Error(int code) {
  for (final entry in directE2eeV2Errors) {
    if (entry.code == code) return entry;
  }
  return null;
}

class V2SignedPrekey {
  const V2SignedPrekey({
    required this.keyId,
    required this.publicKeyB64u,
    required this.expiresAt,
  });

  factory V2SignedPrekey.fromJson(JsonMap value) {
    _exact(value, {'key_id', 'public_key_b64u', 'expires_at'}, 'signed_prekey');
    final result = V2SignedPrekey(
      keyId: _text(value['key_id'], 'signed_prekey.key_id'),
      publicKeyB64u: _text(
        value['public_key_b64u'],
        'signed_prekey.public_key_b64u',
      ),
      expiresAt: _text(value['expires_at'], 'signed_prekey.expires_at'),
    );
    result.validate();
    return result;
  }

  final String keyId;
  final String publicKeyB64u;
  final String expiresAt;

  void validate() {
    _text(keyId, 'signed_prekey.key_id');
    _x25519B64u(publicKeyB64u, 'signed_prekey.public_key_b64u');
    if (DateTime.tryParse(expiresAt) == null) {
      throw const AnpDirectE2eeV2Exception(
        'signed_prekey.expires_at must be RFC3339',
      );
    }
  }

  JsonMap toJson() => {
    'key_id': keyId,
    'public_key_b64u': publicKeyB64u,
    'expires_at': expiresAt,
  };
}

class V2OneTimePrekey {
  const V2OneTimePrekey({required this.keyId, required this.publicKeyB64u});

  factory V2OneTimePrekey.fromJson(JsonMap value) {
    _exact(value, {'key_id', 'public_key_b64u'}, 'one_time_prekey');
    final result = V2OneTimePrekey(
      keyId: _text(value['key_id'], 'one_time_prekey.key_id'),
      publicKeyB64u: _text(
        value['public_key_b64u'],
        'one_time_prekey.public_key_b64u',
      ),
    );
    result.validate();
    return result;
  }

  final String keyId;
  final String publicKeyB64u;

  void validate() {
    _text(keyId, 'one_time_prekey.key_id');
    _x25519B64u(publicKeyB64u, 'one_time_prekey.public_key_b64u');
  }

  JsonMap toJson() => {'key_id': keyId, 'public_key_b64u': publicKeyB64u};
}

class V2PrekeyBundle {
  const V2PrekeyBundle({
    required this.bundleId,
    required this.ownerDid,
    required this.ownerDeviceId,
    required this.suite,
    required this.staticKeyAgreementId,
    required this.signedPrekey,
    required this.proof,
  });

  factory V2PrekeyBundle.fromJson(JsonMap value) {
    _exact(value, {
      'bundle_id',
      'owner_did',
      'owner_device_id',
      'suite',
      'static_key_agreement_id',
      'signed_prekey',
      'proof',
    }, 'prekey_bundle');
    final result = V2PrekeyBundle(
      bundleId: _text(value['bundle_id'], 'prekey_bundle.bundle_id'),
      ownerDid: _text(value['owner_did'], 'prekey_bundle.owner_did'),
      ownerDeviceId: _text(
        value['owner_device_id'],
        'prekey_bundle.owner_device_id',
      ),
      suite: _text(value['suite'], 'prekey_bundle.suite'),
      staticKeyAgreementId: _text(
        value['static_key_agreement_id'],
        'prekey_bundle.static_key_agreement_id',
      ),
      signedPrekey: V2SignedPrekey.fromJson(
        _map(value['signed_prekey'], 'prekey_bundle.signed_prekey'),
      ),
      proof: _map(value['proof'], 'prekey_bundle.proof'),
    );
    result.validateStructure();
    return result;
  }

  final String bundleId;
  final String ownerDid;
  final String ownerDeviceId;
  final String suite;
  final String staticKeyAgreementId;
  final V2SignedPrekey signedPrekey;
  final JsonMap proof;

  void validateStructure() {
    for (final value in [
      bundleId,
      ownerDid,
      ownerDeviceId,
      staticKeyAgreementId,
    ]) {
      _text(value, 'prekey_bundle identifier');
    }
    if (suite != mtiDirectE2eeSuiteV2) {
      throw const AnpDirectE2eeV2Exception('unsupported P5 v2 suite');
    }
    signedPrekey.validate();
    for (final field in [
      'type',
      'cryptosuite',
      'verificationMethod',
      'proofPurpose',
      'created',
      'proofValue',
    ]) {
      _text(proof[field], 'prekey_bundle.proof.$field');
    }
    if (proof['type'] != 'DataIntegrityProof' ||
        proof['cryptosuite'] != 'eddsa-jcs-2022' ||
        proof['proofPurpose'] != 'assertionMethod') {
      throw const AnpDirectE2eeV2Exception(
        'invalid Appendix-B Object Proof profile',
      );
    }
  }

  JsonMap toJson() => {
    'bundle_id': bundleId,
    'owner_did': ownerDid,
    'owner_device_id': ownerDeviceId,
    'suite': suite,
    'static_key_agreement_id': staticKeyAgreementId,
    'signed_prekey': signedPrekey.toJson(),
    'proof': Map<String, Object?>.of(proof),
  };
}

class V2Target {
  const V2Target({required this.kind, required this.did});

  factory V2Target.fromJson(JsonMap value) {
    _exact(value, {'kind', 'did'}, 'meta.target');
    return V2Target(
      kind: _text(value['kind'], 'meta.target.kind'),
      did: _text(value['did'], 'meta.target.did'),
    );
  }

  final String kind;
  final String did;

  JsonMap toJson() => {'kind': kind, 'did': did};
}

class V2KeyServiceMetadata {
  const V2KeyServiceMetadata({
    required this.profile,
    required this.securityProfile,
    required this.senderDid,
    required this.senderDeviceId,
    required this.target,
    required this.operationId,
    this.anpVersion,
    this.createdAt,
  });

  factory V2KeyServiceMetadata.fromJson(JsonMap value) {
    _fields(
      value,
      {
        'profile',
        'security_profile',
        'sender_did',
        'sender_device_id',
        'target',
        'operation_id',
      },
      {'anp_version', 'created_at'},
      'key service meta',
    );
    final result = V2KeyServiceMetadata(
      profile: _text(value['profile'], 'meta.profile'),
      securityProfile: _text(
        value['security_profile'],
        'meta.security_profile',
      ),
      senderDid: _text(value['sender_did'], 'meta.sender_did'),
      senderDeviceId: _text(value['sender_device_id'], 'meta.sender_device_id'),
      target: V2Target.fromJson(_map(value['target'], 'meta.target')),
      operationId: _text(value['operation_id'], 'meta.operation_id'),
      anpVersion: _optionalText(value['anp_version'], 'meta.anp_version'),
      createdAt: _optionalText(value['created_at'], 'meta.created_at'),
    );
    result.validate();
    return result;
  }

  final String profile;
  final String securityProfile;
  final String senderDid;
  final String senderDeviceId;
  final V2Target target;
  final String operationId;
  final String? anpVersion;
  final String? createdAt;

  void validate() {
    if (profile != directE2eeProfileV2 ||
        securityProfile != transportProtectedSecurityProfile ||
        target.kind != 'service') {
      throw const AnpDirectE2eeV2Exception(
        'invalid P5 v2 key-service profile binding',
      );
    }
    for (final value in [senderDid, senderDeviceId, target.did, operationId]) {
      _text(value, 'key-service selector');
    }
    if (anpVersion != null) _text(anpVersion, 'meta.anp_version');
    if (createdAt != null) _rfc3339(createdAt!, 'meta.created_at');
  }

  JsonMap toJson() => {
    if (anpVersion != null) 'anp_version': anpVersion,
    'profile': profile,
    'security_profile': securityProfile,
    'sender_did': senderDid,
    'sender_device_id': senderDeviceId,
    'target': target.toJson(),
    'operation_id': operationId,
    if (createdAt != null) 'created_at': createdAt,
  };
}

class V2DirectMetadata {
  const V2DirectMetadata({
    required this.profile,
    required this.securityProfile,
    required this.senderDid,
    required this.senderDeviceId,
    required this.target,
    required this.recipientDeviceId,
    required this.operationId,
    required this.messageId,
    required this.contentType,
    this.anpVersion,
    this.createdAt,
  });

  factory V2DirectMetadata.fromJson(JsonMap value) {
    _fields(
      value,
      {
        'profile',
        'security_profile',
        'sender_did',
        'sender_device_id',
        'target',
        'recipient_device_id',
        'operation_id',
        'message_id',
        'content_type',
      },
      {'anp_version', 'created_at'},
      'direct meta',
    );
    final result = V2DirectMetadata(
      profile: _text(value['profile'], 'meta.profile'),
      securityProfile: _text(
        value['security_profile'],
        'meta.security_profile',
      ),
      senderDid: _text(value['sender_did'], 'meta.sender_did'),
      senderDeviceId: _text(value['sender_device_id'], 'meta.sender_device_id'),
      target: V2Target.fromJson(_map(value['target'], 'meta.target')),
      recipientDeviceId: _text(
        value['recipient_device_id'],
        'meta.recipient_device_id',
      ),
      operationId: _text(value['operation_id'], 'meta.operation_id'),
      messageId: _text(value['message_id'], 'meta.message_id'),
      contentType: _text(value['content_type'], 'meta.content_type'),
      anpVersion: _optionalText(value['anp_version'], 'meta.anp_version'),
      createdAt: _optionalText(value['created_at'], 'meta.created_at'),
    );
    result.validate();
    return result;
  }

  final String profile;
  final String securityProfile;
  final String senderDid;
  final String senderDeviceId;
  final V2Target target;
  final String recipientDeviceId;
  final String operationId;
  final String messageId;
  final String contentType;
  final String? anpVersion;
  final String? createdAt;

  void validate() {
    if (profile != directE2eeProfileV2 ||
        securityProfile != directE2eeSecurityProfile ||
        target.kind != 'agent' ||
        !{
          contentTypeDirectInitV2,
          contentTypeDirectCipherV2,
        }.contains(contentType)) {
      throw const AnpDirectE2eeV2Exception(
        'invalid P5 v2 direct.send profile binding',
      );
    }
    if (operationId != messageId) {
      throw const AnpDirectE2eeV2Exception(
        'operation_id must equal message_id',
      );
    }
    for (final value in [
      senderDid,
      senderDeviceId,
      target.did,
      recipientDeviceId,
      operationId,
      messageId,
    ]) {
      _text(value, 'direct selector');
    }
    if (anpVersion != null) _text(anpVersion, 'meta.anp_version');
    if (createdAt != null) _rfc3339(createdAt!, 'meta.created_at');
  }

  JsonMap toJson() => {
    if (anpVersion != null) 'anp_version': anpVersion,
    'profile': profile,
    'security_profile': securityProfile,
    'sender_did': senderDid,
    'sender_device_id': senderDeviceId,
    'target': target.toJson(),
    'recipient_device_id': recipientDeviceId,
    'operation_id': operationId,
    'message_id': messageId,
    'content_type': contentType,
    if (createdAt != null) 'created_at': createdAt,
  };

  V2DirectMetadata copyWith({String? anpVersion, String? createdAt}) =>
      V2DirectMetadata(
        profile: profile,
        securityProfile: securityProfile,
        senderDid: senderDid,
        senderDeviceId: senderDeviceId,
        target: target,
        recipientDeviceId: recipientDeviceId,
        operationId: operationId,
        messageId: messageId,
        contentType: contentType,
        anpVersion: anpVersion ?? this.anpVersion,
        createdAt: createdAt ?? this.createdAt,
      );
}

class V2RatchetHeader {
  const V2RatchetHeader({
    required this.dhPubB64u,
    required this.pn,
    required this.n,
  });

  factory V2RatchetHeader.fromJson(JsonMap value) {
    _exact(value, {'dh_pub_b64u', 'pn', 'n'}, 'ratchet_header');
    final result = V2RatchetHeader(
      dhPubB64u: _text(value['dh_pub_b64u'], 'ratchet_header.dh_pub_b64u'),
      pn: _text(value['pn'], 'ratchet_header.pn'),
      n: _text(value['n'], 'ratchet_header.n'),
    );
    result.validate();
    return result;
  }

  void validate() {
    _x25519B64u(dhPubB64u, 'ratchet_header.dh_pub_b64u');
    if (!RegExp(r'^\d+$').hasMatch(pn) || !RegExp(r'^\d+$').hasMatch(n)) {
      throw const AnpDirectE2eeV2Exception(
        'ratchet counters must be decimal strings',
      );
    }
  }

  final String dhPubB64u;
  final String pn;
  final String n;

  JsonMap toJson() => {'dh_pub_b64u': dhPubB64u, 'pn': pn, 'n': n};
}

class V2DirectInitBody {
  const V2DirectInitBody({
    required this.sessionId,
    required this.suite,
    required this.senderStaticKeyAgreementId,
    required this.recipientBundleId,
    required this.recipientSignedPrekeyId,
    required this.senderEphemeralPubB64u,
    required this.ciphertextB64u,
    this.recipientOneTimePrekeyId,
  });

  factory V2DirectInitBody.fromJson(JsonMap value) {
    _fields(
      value,
      {
        'session_id',
        'suite',
        'sender_static_key_agreement_id',
        'recipient_bundle_id',
        'recipient_signed_prekey_id',
        'sender_ephemeral_pub_b64u',
        'ciphertext_b64u',
      },
      {'recipient_one_time_prekey_id'},
      'direct init body',
    );
    final result = V2DirectInitBody(
      sessionId: _text(value['session_id'], 'body.session_id'),
      suite: _text(value['suite'], 'body.suite'),
      senderStaticKeyAgreementId: _text(
        value['sender_static_key_agreement_id'],
        'body.sender_static_key_agreement_id',
      ),
      recipientBundleId: _text(
        value['recipient_bundle_id'],
        'body.recipient_bundle_id',
      ),
      recipientSignedPrekeyId: _text(
        value['recipient_signed_prekey_id'],
        'body.recipient_signed_prekey_id',
      ),
      recipientOneTimePrekeyId: _optionalText(
        value['recipient_one_time_prekey_id'],
        'body.recipient_one_time_prekey_id',
      ),
      senderEphemeralPubB64u: _text(
        value['sender_ephemeral_pub_b64u'],
        'body.sender_ephemeral_pub_b64u',
      ),
      ciphertextB64u: _text(value['ciphertext_b64u'], 'body.ciphertext_b64u'),
    );
    result.validate();
    return result;
  }

  final String sessionId;
  final String suite;
  final String senderStaticKeyAgreementId;
  final String recipientBundleId;
  final String recipientSignedPrekeyId;
  final String? recipientOneTimePrekeyId;
  final String senderEphemeralPubB64u;
  final String ciphertextB64u;

  void validate() {
    if (suite != mtiDirectE2eeSuiteV2) {
      throw const AnpDirectE2eeV2Exception('unsupported P5 v2 suite');
    }
    _fixedB64u(sessionId, 'body.session_id', 16);
    for (final value in [
      senderStaticKeyAgreementId,
      recipientBundleId,
      recipientSignedPrekeyId,
    ]) {
      _text(value, 'direct init identifier');
    }
    if (recipientOneTimePrekeyId != null) {
      _text(recipientOneTimePrekeyId, 'body.recipient_one_time_prekey_id');
    }
    _x25519B64u(senderEphemeralPubB64u, 'body.sender_ephemeral_pub_b64u');
    _base64UrlNoPad(ciphertextB64u, 'body.ciphertext_b64u');
  }

  JsonMap toJson() => {
    'session_id': sessionId,
    'suite': suite,
    'sender_static_key_agreement_id': senderStaticKeyAgreementId,
    'recipient_bundle_id': recipientBundleId,
    'recipient_signed_prekey_id': recipientSignedPrekeyId,
    if (recipientOneTimePrekeyId != null)
      'recipient_one_time_prekey_id': recipientOneTimePrekeyId,
    'sender_ephemeral_pub_b64u': senderEphemeralPubB64u,
    'ciphertext_b64u': ciphertextB64u,
  };
}

class V2DirectCipherBody {
  const V2DirectCipherBody({
    required this.sessionId,
    required this.ratchetHeader,
    required this.ciphertextB64u,
    this.suite,
  });

  factory V2DirectCipherBody.fromJson(JsonMap value) {
    _fields(
      value,
      {'session_id', 'ratchet_header', 'ciphertext_b64u'},
      {'suite'},
      'direct cipher body',
    );
    final result = V2DirectCipherBody(
      sessionId: _text(value['session_id'], 'body.session_id'),
      ratchetHeader: V2RatchetHeader.fromJson(
        _map(value['ratchet_header'], 'body.ratchet_header'),
      ),
      ciphertextB64u: _text(value['ciphertext_b64u'], 'body.ciphertext_b64u'),
      suite: _optionalText(value['suite'], 'body.suite'),
    );
    result.validate();
    return result;
  }

  final String sessionId;
  final String? suite;
  final V2RatchetHeader ratchetHeader;
  final String ciphertextB64u;

  void validate() {
    if (suite != null && suite != mtiDirectE2eeSuiteV2) {
      throw const AnpDirectE2eeV2Exception('cipher suite mismatch');
    }
    _fixedB64u(sessionId, 'body.session_id', 16);
    ratchetHeader.validate();
    _base64UrlNoPad(ciphertextB64u, 'body.ciphertext_b64u');
  }

  JsonMap toJson() => {
    'session_id': sessionId,
    if (suite != null) 'suite': suite,
    'ratchet_header': ratchetHeader.toJson(),
    'ciphertext_b64u': ciphertextB64u,
  };
}

class V2ApplicationPlaintext {
  const V2ApplicationPlaintext({
    required this.applicationContentType,
    this.logicalMessageId,
    this.conversationId,
    this.replyToMessageId,
    this.annotations,
    this.text,
    this.payload,
    this.payloadB64u,
  });

  factory V2ApplicationPlaintext.fromJson(JsonMap value) {
    _fields(
      value,
      {'application_content_type'},
      {
        'logical_message_id',
        'conversation_id',
        'reply_to_message_id',
        'annotations',
        'text',
        'payload',
        'payload_b64u',
      },
      'ApplicationPlaintext',
    );
    final result = V2ApplicationPlaintext(
      applicationContentType: _text(
        value['application_content_type'],
        'application_content_type',
      ),
      logicalMessageId: _optionalText(
        value['logical_message_id'],
        'logical_message_id',
      ),
      conversationId: _optionalText(
        value['conversation_id'],
        'conversation_id',
      ),
      replyToMessageId: _optionalText(
        value['reply_to_message_id'],
        'reply_to_message_id',
      ),
      annotations: value['annotations'] == null
          ? null
          : _map(value['annotations'], 'annotations'),
      text: _optionalText(value['text'], 'text'),
      payload: value['payload'] == null
          ? null
          : _map(value['payload'], 'payload'),
      payloadB64u: _optionalText(value['payload_b64u'], 'payload_b64u'),
    );
    result.validate();
    return result;
  }

  void validate() {
    _text(applicationContentType, 'application_content_type');
    for (final value in [logicalMessageId, conversationId, replyToMessageId]) {
      if (value != null) _text(value, 'optional plaintext identifier');
    }
    if ([text, payload, payloadB64u].where((value) => value != null).length !=
        1) {
      throw const AnpDirectE2eeV2Exception(
        'exactly one plaintext bearer must be present',
      );
    }
    if (payloadB64u != null) {
      _base64UrlNoPad(payloadB64u!, 'payload_b64u');
    }
    if (applicationContentType == 'text/plain' && text == null) {
      throw const AnpDirectE2eeV2Exception(
        'text/plain requires the text bearer',
      );
    }
    if ({
          'application/json',
          'application/anp-attachment-manifest+json',
        }.contains(applicationContentType) &&
        payload == null) {
      throw AnpDirectE2eeV2Exception(
        '$applicationContentType requires the payload bearer',
      );
    }
  }

  final String applicationContentType;
  final String? logicalMessageId;
  final String? conversationId;
  final String? replyToMessageId;
  final JsonMap? annotations;
  final String? text;
  final JsonMap? payload;
  final String? payloadB64u;

  JsonMap toJson() => {
    'application_content_type': applicationContentType,
    if (logicalMessageId != null) 'logical_message_id': logicalMessageId,
    if (conversationId != null) 'conversation_id': conversationId,
    if (replyToMessageId != null) 'reply_to_message_id': replyToMessageId,
    if (annotations != null) 'annotations': annotations,
    if (text != null) 'text': text,
    if (payload != null) 'payload': payload,
    if (payloadB64u != null) 'payload_b64u': payloadB64u,
  };
}

class V2PublishPrekeyBundleResult {
  const V2PublishPrekeyBundleResult({
    required this.published,
    required this.ownerDid,
    required this.ownerDeviceId,
    required this.bundleId,
    required this.publishedAt,
    this.publishedOpkCount,
  });

  factory V2PublishPrekeyBundleResult.fromJson(JsonMap value) {
    _fields(
      value,
      {
        'published',
        'owner_did',
        'owner_device_id',
        'bundle_id',
        'published_at',
      },
      {'published_opk_count'},
      'publish result',
    );
    if (value['published'] != true) {
      throw const AnpDirectE2eeV2Exception(
        'published must be true in a successful result',
      );
    }
    final publishedOpkCount = value['published_opk_count'];
    if (publishedOpkCount != null &&
        (publishedOpkCount is! int || publishedOpkCount < 0)) {
      throw const AnpDirectE2eeV2Exception(
        'published_opk_count must be a non-negative integer',
      );
    }
    final publishedAt = _text(value['published_at'], 'published_at');
    _rfc3339(publishedAt, 'published_at');
    return V2PublishPrekeyBundleResult(
      published: true,
      ownerDid: _text(value['owner_did'], 'owner_did'),
      ownerDeviceId: _text(value['owner_device_id'], 'owner_device_id'),
      bundleId: _text(value['bundle_id'], 'bundle_id'),
      publishedAt: publishedAt,
      publishedOpkCount: publishedOpkCount as int?,
    );
  }

  final bool published;
  final String ownerDid;
  final String ownerDeviceId;
  final String bundleId;
  final String publishedAt;
  final int? publishedOpkCount;
}

class V2GetPrekeyBundleResult {
  const V2GetPrekeyBundleResult({
    required this.targetDid,
    required this.targetDeviceId,
    required this.prekeyBundle,
    this.oneTimePrekey,
  });

  factory V2GetPrekeyBundleResult.fromJson(JsonMap value) {
    _fields(
      value,
      {'target_did', 'target_device_id', 'prekey_bundle'},
      {'one_time_prekey'},
      'get result',
    );
    final targetDid = _text(value['target_did'], 'target_did');
    final targetDeviceId = _text(value['target_device_id'], 'target_device_id');
    final bundle = V2PrekeyBundle.fromJson(
      _map(value['prekey_bundle'], 'prekey_bundle'),
    );
    if (bundle.ownerDid != targetDid ||
        bundle.ownerDeviceId != targetDeviceId) {
      throw const AnpDirectE2eeV2Exception(
        'get result target must equal the returned bundle owner',
      );
    }
    return V2GetPrekeyBundleResult(
      targetDid: targetDid,
      targetDeviceId: targetDeviceId,
      prekeyBundle: bundle,
      oneTimePrekey: value['one_time_prekey'] == null
          ? null
          : V2OneTimePrekey.fromJson(
              _map(value['one_time_prekey'], 'one_time_prekey'),
            ),
    );
  }

  final String targetDid;
  final String targetDeviceId;
  final V2PrekeyBundle prekeyBundle;
  final V2OneTimePrekey? oneTimePrekey;
}

class V2DirectSendResult {
  const V2DirectSendResult({
    required this.accepted,
    required this.messageId,
    required this.operationId,
    required this.targetDid,
    required this.recipientDeviceId,
    required this.acceptedAt,
  });

  factory V2DirectSendResult.fromJson(JsonMap value) {
    _exact(value, {
      'accepted',
      'message_id',
      'operation_id',
      'target_did',
      'recipient_device_id',
      'accepted_at',
    }, 'direct.send result');
    if (value['accepted'] != true) {
      throw const AnpDirectE2eeV2Exception(
        'accepted must be true in a successful result',
      );
    }
    final messageId = _text(value['message_id'], 'message_id');
    final operationId = _text(value['operation_id'], 'operation_id');
    if (messageId != operationId) {
      throw const AnpDirectE2eeV2Exception(
        'result.operation_id must equal result.message_id',
      );
    }
    final acceptedAt = _text(value['accepted_at'], 'accepted_at');
    _rfc3339(acceptedAt, 'accepted_at');
    return V2DirectSendResult(
      accepted: true,
      messageId: messageId,
      operationId: operationId,
      targetDid: _text(value['target_did'], 'target_did'),
      recipientDeviceId: _text(
        value['recipient_device_id'],
        'recipient_device_id',
      ),
      acceptedAt: acceptedAt,
    );
  }

  final bool accepted;
  final String messageId;
  final String operationId;
  final String targetDid;
  final String recipientDeviceId;
  final String acceptedAt;
}

V2PublishPrekeyBundleResult parsePublishPrekeyBundleResultV2(JsonMap value) =>
    V2PublishPrekeyBundleResult.fromJson(value);

V2GetPrekeyBundleResult parseGetPrekeyBundleResultV2(JsonMap value) =>
    V2GetPrekeyBundleResult.fromJson(value);

V2DirectSendResult parseDirectSendResultV2(JsonMap value) =>
    V2DirectSendResult.fromJson(value);

String signedBundleObjectJcsV2(V2PrekeyBundle bundle) {
  final value = bundle.toJson()..remove('proof');
  return canonicalJson(value);
}

List<int> buildInitAadV2(V2DirectMetadata meta, V2DirectInitBody body) {
  meta.validate();
  body.validate();
  if (meta.contentType != contentTypeDirectInitV2) {
    throw const AnpDirectE2eeV2Exception('init AAD content_type mismatch');
  }
  return canonicalJsonBytes({
    'content_type': contentTypeDirectInitV2,
    'message_id': meta.messageId,
    'operation_id': meta.operationId,
    'profile': meta.profile,
    'security_profile': meta.securityProfile,
    'sender_did': meta.senderDid,
    'sender_device_id': meta.senderDeviceId,
    'recipient_did': meta.target.did,
    'recipient_device_id': meta.recipientDeviceId,
    'suite': body.suite,
    'recipient_bundle_id': body.recipientBundleId,
    'sender_static_key_agreement_id': body.senderStaticKeyAgreementId,
    'recipient_signed_prekey_id': body.recipientSignedPrekeyId,
    if (body.recipientOneTimePrekeyId != null)
      'recipient_one_time_prekey_id': body.recipientOneTimePrekeyId,
    'session_id': body.sessionId,
  });
}

List<int> buildMessageAadV2(V2DirectMetadata meta, V2DirectCipherBody body) {
  meta.validate();
  body.validate();
  if (meta.contentType != contentTypeDirectCipherV2) {
    throw const AnpDirectE2eeV2Exception('message AAD content_type mismatch');
  }
  return canonicalJsonBytes({
    'content_type': contentTypeDirectCipherV2,
    'message_id': meta.messageId,
    'operation_id': meta.operationId,
    'profile': meta.profile,
    'security_profile': meta.securityProfile,
    'sender_did': meta.senderDid,
    'sender_device_id': meta.senderDeviceId,
    'recipient_did': meta.target.did,
    'recipient_device_id': meta.recipientDeviceId,
    'session_id': body.sessionId,
    'ratchet_header': body.ratchetHeader.toJson(),
  });
}

List<int> canonicalApplicationPlaintextV2(V2ApplicationPlaintext value) {
  value.validate();
  return canonicalJsonBytes(value.toJson());
}

JsonMap directSendRequestV2(V2DirectMetadata meta, Object body) {
  meta.validate();
  final JsonMap bodyValue;
  if (body is V2DirectInitBody && meta.contentType == contentTypeDirectInitV2) {
    body.validate();
    bodyValue = body.toJson();
  } else if (body is V2DirectCipherBody &&
      meta.contentType == contentTypeDirectCipherV2) {
    body.validate();
    bodyValue = body.toJson();
  } else {
    throw const AnpDirectE2eeV2Exception('direct body/content_type mismatch');
  }
  return {
    'method': 'direct.send',
    'params': {'meta': meta.toJson(), 'body': bodyValue},
  };
}

(V2DirectMetadata, Object) parseDirectSendRequestV2(JsonMap value) {
  final params = _request(value, 'direct.send');
  final meta = V2DirectMetadata.fromJson(_map(params['meta'], 'params.meta'));
  final bodyMap = _map(params['body'], 'params.body');
  final Object body = meta.contentType == contentTypeDirectInitV2
      ? V2DirectInitBody.fromJson(bodyMap)
      : V2DirectCipherBody.fromJson(bodyMap);
  directSendRequestV2(meta, body);
  return (meta, body);
}

JsonMap publishPrekeyBundleRequestV2(
  V2KeyServiceMetadata meta,
  V2PrekeyBundle bundle, {
  List<V2OneTimePrekey> oneTimePrekeys = const [],
}) {
  meta.validate();
  bundle.validateStructure();
  for (final oneTimePrekey in oneTimePrekeys) {
    oneTimePrekey.validate();
  }
  if (bundle.ownerDid != meta.senderDid ||
      bundle.ownerDeviceId != meta.senderDeviceId) {
    throw const AnpDirectE2eeV2Exception(
      'published bundle owner must equal sending device',
    );
  }
  return {
    'method': 'direct.e2ee.publish_prekey_bundle',
    'params': {
      'meta': meta.toJson(),
      'body': {
        'prekey_bundle': bundle.toJson(),
        if (oneTimePrekeys.isNotEmpty)
          'one_time_prekeys': oneTimePrekeys
              .map((entry) => entry.toJson())
              .toList(),
      },
    },
  };
}

(V2KeyServiceMetadata, V2PrekeyBundle, List<V2OneTimePrekey>)
parsePublishPrekeyBundleRequestV2(JsonMap value) {
  final params = _request(value, 'direct.e2ee.publish_prekey_bundle');
  final meta = V2KeyServiceMetadata.fromJson(
    _map(params['meta'], 'params.meta'),
  );
  final body = _map(params['body'], 'params.body');
  _fields(body, {'prekey_bundle'}, {'one_time_prekeys'}, 'publish body');
  final bundle = V2PrekeyBundle.fromJson(
    _map(body['prekey_bundle'], 'body.prekey_bundle'),
  );
  final rawOpks = body['one_time_prekeys'];
  final opks = rawOpks == null
      ? <V2OneTimePrekey>[]
      : _nonEmptyList(rawOpks, 'body.one_time_prekeys')
            .map(
              (entry) => V2OneTimePrekey.fromJson(
                _map(entry, 'body.one_time_prekeys[]'),
              ),
            )
            .toList();
  publishPrekeyBundleRequestV2(meta, bundle, oneTimePrekeys: opks);
  return (meta, bundle, opks);
}

JsonMap getPrekeyBundleRequestV2(
  V2KeyServiceMetadata meta, {
  required String targetDid,
  required String targetDeviceId,
  String? preferredSuite,
  bool? requireOpk,
}) {
  meta.validate();
  _text(targetDid, 'body.target_did');
  _text(targetDeviceId, 'body.target_device_id');
  if (preferredSuite != null) {
    _text(preferredSuite, 'body.preferred_suite');
  }
  return {
    'method': 'direct.e2ee.get_prekey_bundle',
    'params': {
      'meta': meta.toJson(),
      'body': {
        'target_did': targetDid,
        'target_device_id': targetDeviceId,
        if (preferredSuite != null) 'preferred_suite': preferredSuite,
        if (requireOpk != null) 'require_opk': requireOpk,
      },
    },
  };
}

(V2KeyServiceMetadata, JsonMap) parseGetPrekeyBundleRequestV2(JsonMap value) {
  final params = _request(value, 'direct.e2ee.get_prekey_bundle');
  final meta = V2KeyServiceMetadata.fromJson(
    _map(params['meta'], 'params.meta'),
  );
  final body = _map(params['body'], 'params.body');
  _fields(
    body,
    {'target_did', 'target_device_id'},
    {'preferred_suite', 'require_opk'},
    'get body',
  );
  final requireOpk = body['require_opk'];
  if (requireOpk != null && requireOpk is! bool) {
    throw const AnpDirectE2eeV2Exception('require_opk must be a boolean');
  }
  final rebuilt = getPrekeyBundleRequestV2(
    meta,
    targetDid: _text(body['target_did'], 'body.target_did'),
    targetDeviceId: _text(body['target_device_id'], 'body.target_device_id'),
    preferredSuite: _optionalText(
      body['preferred_suite'],
      'body.preferred_suite',
    ),
    requireOpk: requireOpk as bool?,
  );
  return (meta, _map(_map(rebuilt['params'], 'params')['body'], 'body'));
}

void validatePrekeyBundleV2Binding(
  V2PrekeyBundle bundle,
  JsonMap didDocument, {
  required DateTime now,
}) {
  bundle.validateStructure();
  if (didDocument['id'] != bundle.ownerDid) {
    throw const AnpDirectE2eeV2Exception('invalid bundle owner or suite');
  }
  final device = findEligibleDevice(
    didDocument,
    bundle.ownerDeviceId,
    profileDirectE2eeV2,
  );
  if (device == null ||
      device.e2eeKeyId != bundle.staticKeyAgreementId ||
      bundle.proof['verificationMethod'] != device.signingKeyId ||
      bundle.proof['type'] != 'DataIntegrityProof' ||
      bundle.proof['cryptosuite'] != 'eddsa-jcs-2022' ||
      bundle.proof['proofPurpose'] != 'assertionMethod') {
    throw const AnpDirectE2eeV2Exception(
      'invalid bundle Device Manifest or Object Proof binding',
    );
  }
  final expiry = DateTime.tryParse(bundle.signedPrekey.expiresAt)?.toUtc();
  if (expiry == null || !expiry.isAfter(now.toUtc())) {
    throw const AnpDirectE2eeV2Exception('signed prekey is expired');
  }
}

Future<void> verifyPrekeyBundleV2(
  V2PrekeyBundle bundle,
  JsonMap didDocument,
  MessageVerifier verifier, {
  required DateTime now,
}) async {
  validatePrekeyBundleV2Binding(bundle, didDocument, now: now);
  if (!await verifyObjectProof(bundle.toJson(), verifier)) {
    throw const AnpDirectE2eeV2Exception('bundle Object Proof is invalid');
  }
}

JsonMap _request(JsonMap value, String method) {
  _exact(value, {'method', 'params'}, 'request');
  if (value['method'] != method) {
    throw AnpDirectE2eeV2Exception('request method must equal $method');
  }
  final params = _map(value['params'], 'params');
  _exact(params, {'meta', 'body'}, 'params');
  return params;
}

void _exact(JsonMap value, Set<String> expected, String subject) {
  if (value.length != expected.length ||
      value.keys.any((key) => !expected.contains(key))) {
    throw AnpDirectE2eeV2Exception('$subject has unexpected or missing fields');
  }
}

void _fields(
  JsonMap value,
  Set<String> required,
  Set<String> optional,
  String subject,
) {
  if (!value.keys.toSet().containsAll(required) ||
      value.keys.any(
        (key) => !required.contains(key) && !optional.contains(key),
      )) {
    throw AnpDirectE2eeV2Exception('$subject has unexpected or missing fields');
  }
  for (final field in optional) {
    if (value.containsKey(field) && value[field] == null) {
      throw AnpDirectE2eeV2Exception(
        '$subject.$field must be omitted rather than null',
      );
    }
  }
}

JsonMap _map(Object? value, String subject) {
  if (value is! Map || value.keys.any((key) => key is! String)) {
    throw AnpDirectE2eeV2Exception('$subject must be an object');
  }
  return Map<String, Object?>.from(value);
}

String _text(Object? value, String subject) {
  if (value is! String || value.isEmpty) {
    throw AnpDirectE2eeV2Exception('$subject must be a non-empty string');
  }
  return value;
}

String? _optionalText(Object? value, String subject) =>
    value == null ? null : _text(value, subject);

void _rfc3339(String value, String subject) {
  if (DateTime.tryParse(value) == null ||
      !RegExp(r'T.*(?:Z|[+-]\d{2}:\d{2})$').hasMatch(value)) {
    throw AnpDirectE2eeV2Exception('$subject must be RFC3339');
  }
}

List<Object?> _nonEmptyList(Object? value, String subject) {
  if (value is! List<Object?> || value.isEmpty) {
    throw AnpDirectE2eeV2Exception('$subject must be a non-empty array');
  }
  return value;
}

void _x25519B64u(String value, String subject) {
  _fixedB64u(value, subject, 32);
}

void _fixedB64u(String value, String subject, int expectedLength) {
  final decoded = _decodeBase64UrlNoPad(value, subject);
  if (decoded.length != expectedLength) {
    throw AnpDirectE2eeV2Exception(
      '$subject must encode $expectedLength bytes',
    );
  }
}

void _base64UrlNoPad(String value, String subject) {
  _decodeBase64UrlNoPad(value, subject);
}

List<int> _decodeBase64UrlNoPad(String value, String subject) {
  if (value.contains('=') ||
      value.isEmpty ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    throw AnpDirectE2eeV2Exception('$subject must be unpadded base64url');
  }
  try {
    final padded = value.padRight(((value.length + 3) ~/ 4) * 4, '=');
    return base64Url.decode(padded);
  } on FormatException catch (error) {
    throw AnpDirectE2eeV2Exception('$subject must be base64url', cause: error);
  }
}
