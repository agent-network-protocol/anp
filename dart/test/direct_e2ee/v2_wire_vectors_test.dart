import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  final vectors = _loadVectors();

  test('shared P5 v2 bundle and key-service requests round trip', () {
    final bundle = V2PrekeyBundle.fromJson(_map(vectors['prekey_bundle']));
    expect(
      signedBundleObjectJcsV2(bundle),
      vectors['expected_signed_bundle_object_jcs'],
    );

    final (publishMeta, publishBundle, opks) =
        parsePublishPrekeyBundleRequestV2(_map(vectors['publish_request']));
    expect(
      publishPrekeyBundleRequestV2(
        publishMeta,
        publishBundle,
        oneTimePrekeys: opks,
      ),
      equals(vectors['publish_request']),
    );

    final (getMeta, getBody) = parseGetPrekeyBundleRequestV2(
      _map(vectors['get_request']),
    );
    expect(
      getPrekeyBundleRequestV2(
        getMeta,
        targetDid: getBody['target_did']! as String,
        targetDeviceId: getBody['target_device_id']! as String,
        preferredSuite: getBody['preferred_suite'] as String?,
        requireOpk: getBody['require_opk'] as bool?,
      ),
      equals(vectors['get_request']),
    );

    expect(
      parsePublishPrekeyBundleResultV2(_map(vectors['publish_result'])),
      isA<V2PublishPrekeyBundleResult>(),
    );
    expect(
      parseGetPrekeyBundleResultV2(_map(vectors['get_result'])),
      isA<V2GetPrekeyBundleResult>(),
    );
    expect(
      parseDirectSendResultV2(_map(vectors['direct_send_result'])),
      isA<V2DirectSendResult>(),
    );

    final invalidGet = _clone(vectors['get_result'])
      ..['target_device_id'] = 'dev-sibling';
    expect(
      () => parseGetPrekeyBundleResultV2(invalidGet),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
    final invalidDirect = _clone(vectors['direct_send_result'])
      ..['operation_id'] = 'different-operation';
    expect(
      () => parseDirectSendResultV2(invalidDirect),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
    final invalidPublish = _clone(vectors['publish_result'])
      ..['unexpected'] = true;
    expect(
      () => parsePublishPrekeyBundleResultV2(invalidPublish),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('shared P5 v2 AAD and ApplicationPlaintext vectors match', () {
    final (initMeta, rawInit) = parseDirectSendRequestV2(
      _map(vectors['direct_init_request']),
    );
    final init = rawInit as V2DirectInitBody;
    expect(
      utf8.decode(buildInitAadV2(initMeta, init)),
      vectors['expected_ad_init'],
    );
    expect(
      directSendRequestV2(initMeta, init),
      equals(vectors['direct_init_request']),
    );

    final (cipherMeta, rawCipher) = parseDirectSendRequestV2(
      _map(vectors['direct_cipher_request']),
    );
    final cipher = rawCipher as V2DirectCipherBody;
    expect(
      utf8.decode(buildMessageAadV2(cipherMeta, cipher)),
      vectors['expected_ad_msg'],
    );
    final plaintext = V2ApplicationPlaintext.fromJson(
      _map(vectors['application_plaintext']),
    );
    expect(
      utf8.decode(canonicalApplicationPlaintextV2(plaintext)),
      vectors['expected_application_plaintext_jcs'],
    );
    final numeric = V2ApplicationPlaintext.fromJson(
      _map(vectors['application_plaintext_numeric']),
    );
    expect(
      utf8.decode(canonicalApplicationPlaintextV2(numeric)),
      vectors['expected_application_plaintext_numeric_jcs'],
    );
  });

  test('device tamper changes AAD and private/aggregate fields fail', () {
    final request = _clone(vectors['direct_init_request']);
    final params = _map(request['params']);
    final meta = _map(params['meta']);
    meta['recipient_device_id'] = 'dev-sibling';
    params['meta'] = meta;
    request['params'] = params;
    final (parsedMeta, body) = parseDirectSendRequestV2(request);
    expect(
      utf8.decode(buildInitAadV2(parsedMeta, body as V2DirectInitBody)),
      isNot(vectors['expected_ad_init']),
    );

    final senderTampered = _clone(vectors['direct_init_request']);
    final senderParams = _map(senderTampered['params']);
    final senderMeta = _map(senderParams['meta']);
    senderMeta['sender_device_id'] = 'dev-sender-sibling';
    senderParams['meta'] = senderMeta;
    senderTampered['params'] = senderParams;
    final (parsedSenderMeta, senderBody) = parseDirectSendRequestV2(
      senderTampered,
    );
    expect(
      utf8.decode(
        buildInitAadV2(parsedSenderMeta, senderBody as V2DirectInitBody),
      ),
      isNot(vectors['expected_ad_init']),
    );

    for (final field in [
      'auth',
      'deliveries',
      'root_private_key',
      'document_version',
    ]) {
      final invalid = _clone(vectors['direct_init_request']);
      final invalidParams = _map(invalid['params'])
        ..[field] = <String, Object?>{};
      invalid['params'] = invalidParams;
      expect(
        () => parseDirectSendRequestV2(invalid),
        throwsA(isA<AnpDirectE2eeV2Exception>()),
      );
    }
    final invalid = _clone(vectors['direct_init_request']);
    final invalidParams = _map(invalid['params']);
    final invalidMeta = _map(invalidParams['meta'])
      ..['logical_message_id'] = 'outer-logical';
    invalidParams['meta'] = invalidMeta;
    invalid['params'] = invalidParams;
    expect(
      () => parseDirectSendRequestV2(invalid),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );

    final operationMismatch = _clone(vectors['direct_init_request']);
    final mismatchParams = _map(operationMismatch['params']);
    final mismatchMeta = _map(mismatchParams['meta'])
      ..['operation_id'] = 'different-operation';
    mismatchParams['meta'] = mismatchMeta;
    operationMismatch['params'] = mismatchParams;
    expect(
      () => parseDirectSendRequestV2(operationMismatch),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('publish rejects empty OPK arrays and invalid X25519 key encodings', () {
    final emptyOpks = _clone(vectors['publish_request']);
    final emptyParams = _map(emptyOpks['params']);
    final emptyBody = _map(emptyParams['body'])
      ..['one_time_prekeys'] = <Object?>[];
    emptyParams['body'] = emptyBody;
    emptyOpks['params'] = emptyParams;
    expect(
      () => parsePublishPrekeyBundleRequestV2(emptyOpks),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );

    final badKey = _clone(vectors['publish_request']);
    final badParams = _map(badKey['params']);
    final badBody = _map(badParams['body']);
    final badBundle = _map(badBody['prekey_bundle']);
    final badSignedPrekey = _map(badBundle['signed_prekey'])
      ..['public_key_b64u'] = 'AA==';
    badBundle['signed_prekey'] = badSignedPrekey;
    badBody['prekey_bundle'] = badBundle;
    badParams['body'] = badBody;
    badKey['params'] = badParams;
    expect(
      () => parsePublishPrekeyBundleRequestV2(badKey),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );

    final (meta, bundle, _) = parsePublishPrekeyBundleRequestV2(
      _map(vectors['publish_request']),
    );
    final invalidOpk = V2OneTimePrekey(
      keyId: 'opk-invalid',
      publicKeyB64u: 'AA==',
    );
    expect(
      () => publishPrekeyBundleRequestV2(
        meta,
        bundle,
        oneTimePrekeys: [invalidOpk],
      ),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('shared invalid P5 wire encodings are rejected', () {
    final invalidValues = _map(vectors['encoding_negative_values']);

    JsonMap invalidRequest(
      String requestName,
      void Function(JsonMap params) change,
    ) {
      final request = _clone(vectors[requestName]);
      final params = _map(request['params']);
      change(params);
      request['params'] = params;
      return request;
    }

    final requests = <JsonMap>[
      invalidRequest('direct_init_request', (params) {
        final body = _map(params['body'])
          ..['session_id'] = invalidValues['session_id'];
        params['body'] = body;
      }),
      invalidRequest('direct_init_request', (params) {
        final body = _map(params['body'])
          ..['sender_ephemeral_pub_b64u'] = invalidValues['x25519_public_key'];
        params['body'] = body;
      }),
      invalidRequest('direct_init_request', (params) {
        final body = _map(params['body'])
          ..['ciphertext_b64u'] = invalidValues['ciphertext_b64u'];
        params['body'] = body;
      }),
      invalidRequest('direct_cipher_request', (params) {
        final body = _map(params['body']);
        final header = _map(body['ratchet_header'])
          ..['dh_pub_b64u'] = invalidValues['x25519_public_key'];
        body['ratchet_header'] = header;
        params['body'] = body;
      }),
      invalidRequest('direct_cipher_request', (params) {
        final meta = _map(params['meta'])
          ..['created_at'] = invalidValues['created_at'];
        params['meta'] = meta;
      }),
    ];
    for (final request in requests) {
      expect(
        () => parseDirectSendRequestV2(request),
        throwsA(isA<AnpDirectE2eeV2Exception>()),
      );
    }
    expect(
      () => V2ApplicationPlaintext.fromJson({
        'application_content_type': 'application/octet-stream',
        'payload_b64u': invalidValues['payload_b64u'],
      }),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('optional outer fields do not enter AAD and errors are exact', () {
    final (meta, body) = parseDirectSendRequestV2(
      _map(vectors['direct_init_request']),
    );
    final original = buildInitAadV2(meta, body as V2DirectInitBody);
    final changed = buildInitAadV2(
      meta.copyWith(anpVersion: '9.9', createdAt: '2030-01-01T00:00:00Z'),
      body,
    );
    expect(changed, original);

    final errors = vectors['errors']! as List<Object?>;
    expect(directE2eeV2Errors, hasLength(13));
    for (final raw in errors) {
      final expected = _map(raw);
      expect(
        directE2eeV2Error(expected['code']! as int)?.anpCode,
        expected['anp_code'],
      );
    }
    expect(directE2eeV2Error(5000), isNull);
  });

  test('bundle binding selects the exact Manifest device and proof key', () {
    final bundle = V2PrekeyBundle.fromJson(_map(vectors['prekey_bundle']));
    final did = bundle.ownerDid;
    final document = <String, Object?>{
      'id': did,
      'verificationMethod': [
        {
          'id': '$did#dev-b-sign',
          'type': 'Multikey',
          'controller': did,
          'publicKeyMultibase': 'zSign',
        },
        {
          'id': '$did#dev-b-e2ee',
          'type': 'Multikey',
          'controller': did,
          'publicKeyMultibase': 'zE2ee',
        },
      ],
      'assertionMethod': ['$did#dev-b-sign'],
      'keyAgreement': ['$did#dev-b-e2ee'],
      'deviceManifest': {
        'type': 'ANPDeviceManifest',
        'devices': [
          {
            'device_id': bundle.ownerDeviceId,
            'signing_key_id': '$did#dev-b-sign',
            'e2ee_key_id': '$did#dev-b-e2ee',
            'profiles': [
              'anp.core.binding.v2',
              'anp.identity.discovery.v2',
              'anp.direct.base.v2',
              'anp.direct.e2ee.v2',
            ],
          },
        ],
      },
    };
    validatePrekeyBundleV2Binding(
      bundle,
      document,
      now: DateTime.utc(2026, 7, 19),
    );
    final tampered = bundle.toJson()..['owner_device_id'] = 'dev-sibling';
    expect(
      () => validatePrekeyBundleV2Binding(
        V2PrekeyBundle.fromJson(tampered),
        document,
        now: DateTime.utc(2026, 7, 19),
      ),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('shared cross-language signed Bundle proof verifies', () async {
    final golden = _map(vectors['signed_bundle_golden']);
    final bundle = V2PrekeyBundle.fromJson(_map(golden['prekey_bundle']));
    final didDocument = _map(golden['did_document']);
    final keyId = bundle.proof['verificationMethod']! as String;
    final method = findVerificationMethod(didDocument, keyId)!;
    final verifier = PublicKeyMessageVerifier({
      keyId: extractPublicKey(method),
    });
    await verifyPrekeyBundleV2(
      bundle,
      didDocument,
      verifier,
      now: DateTime.parse(golden['now']! as String),
    );

    final tampered = bundle.toJson();
    final signedPrekey = _map(tampered['signed_prekey'])
      ..['key_id'] = 'spk-tampered';
    tampered['signed_prekey'] = signedPrekey;
    await expectLater(
      () => verifyPrekeyBundleV2(
        V2PrekeyBundle.fromJson(tampered),
        didDocument,
        verifier,
        now: DateTime.parse(golden['now']! as String),
      ),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );
  });

  test('rejects explicit nulls and content bearer mismatches', () {
    final nullOpk = _clone(vectors['direct_init_request']);
    final nullOpkParams = _map(nullOpk['params']);
    final nullOpkBody = _map(nullOpkParams['body'])
      ..['recipient_one_time_prekey_id'] = null;
    nullOpk['params'] = {...nullOpkParams, 'body': nullOpkBody};
    expect(
      () => parseDirectSendRequestV2(nullOpk),
      throwsA(isA<AnpDirectE2eeV2Exception>()),
    );

    for (final field in ['preferred_suite', 'require_opk']) {
      final request = _clone(vectors['get_request']);
      final params = _map(request['params']);
      final body = _map(params['body'])..[field] = null;
      request['params'] = {...params, 'body': body};
      expect(
        () => parseGetPrekeyBundleRequestV2(request),
        throwsA(isA<AnpDirectE2eeV2Exception>()),
      );
    }

    for (final plaintext in <JsonMap>[
      {
        'application_content_type': 'text/plain',
        'payload': <String, Object?>{},
      },
      {'application_content_type': 'application/json', 'text': 'wrong'},
      {
        'application_content_type': 'application/json',
        'annotations': <Object?>[],
        'payload': <String, Object?>{},
      },
      {
        'application_content_type': 'application/json',
        'annotations': null,
        'payload': <String, Object?>{},
      },
    ]) {
      expect(
        () => V2ApplicationPlaintext.fromJson(plaintext),
        throwsA(isA<AnpDirectE2eeV2Exception>()),
      );
    }
  });
}

JsonMap _loadVectors() {
  final path = File('../testdata/direct_e2ee/p5_v2_wire_vectors.json').absolute;
  return _map(jsonDecode(path.readAsStringSync()));
}

JsonMap _clone(Object? value) => _map(jsonDecode(jsonEncode(value)));

JsonMap _map(Object? value) => Map<String, Object?>.from(
  (value! as Map<Object?, Object?>).cast<String, Object?>(),
);
