import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('generates and verifies W3C proof shape', () async {
    final key = generatePrivateKeyMaterial(KeyType.ed25519);
    final signer = PrivateKeyMessageSigner(
      keyId: 'did:wba:example.com#key-1',
      privateKey: key,
    );
    final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey()});
    final signed = await generateW3cProof(
      {'id': 'doc-1'},
      signer,
      signer.keyId,
    );
    expect(signed['proof'], isA<Map<Object?, Object?>>());
    expect(await verifyW3cProof(signed, verifier), isTrue);
  });

  test(
    'Appendix-B Object Proof uses interoperable multibase signatures',
    () async {
      final key = generatePrivateKeyMaterial(KeyType.ed25519);
      const keyId = 'did:wba:example.com:agents:alice#device-sign';
      final signer = PrivateKeyMessageSigner(keyId: keyId, privateKey: key);
      final verifier = PublicKeyMessageVerifier({keyId: key.publicKey()});
      final signed = await generateObjectProof(
        {'id': 'object-1', 'value': 'hello'},
        signer,
        keyId,
        created: DateTime.utc(2026, 7, 19),
      );

      final proof = Map<String, Object?>.from(
        (signed['proof']! as Map).cast<String, Object?>(),
      );
      expect(proof['proofValue'], startsWith('z'));
      expect(await verifyObjectProof(signed, verifier), isTrue);

      final tampered = Map<String, Object?>.from(signed)..['value'] = 'changed';
      expect(await verifyObjectProof(tampered, verifier), isFalse);
      final wrongEncoding = Map<String, Object?>.from(signed)
        ..['proof'] = {...proof, 'proofValue': 'not-multibase'};
      expect(await verifyObjectProof(wrongEncoding, verifier), isFalse);
    },
  );

  test('verifies the shared Rust/Python/Go Appendix-B proof vector', () async {
    final fixture = Map<String, Object?>.from(
      (jsonDecode(
                File(
                  '../testdata/group_e2ee/did_wba_binding_golden.json',
                ).readAsStringSync(),
              )
              as Map)
          .cast<String, Object?>(),
    );
    final document = Map<String, Object?>.from(
      (fixture['did_document']! as Map).cast<String, Object?>(),
    );
    final binding = Map<String, Object?>.from(
      (fixture['did_wba_binding']! as Map).cast<String, Object?>(),
    );
    final keyId = fixture['verification_method']! as String;
    final method = findVerificationMethod(document, keyId)!;
    final verifier = PublicKeyMessageVerifier({
      keyId: extractPublicKey(method),
    });

    expect(await verifyObjectProof(binding, verifier), isTrue);
  });

  test('generates and verifies RFC9421 origin proof', () async {
    final bundle = createDidWbaDocument(
      'example.com',
      options: const DidDocumentOptions(pathSegments: ['user', 'alice']),
    );
    final did = bundle.did;
    final key = bundle.keys[vmKeyAuth]!;
    final signer = PrivateKeyMessageSigner(
      keyId: '$did#key-1',
      privateKey: key.privateKey,
    );
    final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey});
    final meta = <String, Object?>{
      'anp_version': '1.0',
      'profile': 'anp.direct.base.v1',
      'security_profile': 'transport-protected',
      'sender_did': did,
      'target': <String, Object?>{
        'kind': 'agent',
        'did': 'did:wba:example.com:user:bob:e1_peer',
      },
      'operation_id': 'op-1',
      'message_id': 'msg-1',
      'content_type': 'text/plain',
    };
    final body = <String, Object?>{'text': 'hello'};

    final proof = await generateRfc9421OriginProof(
      'direct.send',
      meta,
      body,
      signer,
      options: const Rfc9421OriginProofGenerationOptions(
        created: 1712000000,
        nonce: 'nonce-1',
      ),
    );
    final parsed = await verifyRfc9421OriginProof(
      proof,
      'direct.send',
      meta,
      body,
      verifier,
      options: Rfc9421OriginProofVerificationOptions(expectedSignerDid: did),
    );

    expect(parsed.label, 'sig1');
    expect(parsed.components, rfc9421OriginProofDefaultComponents);
    expect(parsed.created, 1712000000);
    expect(parsed.nonce, 'nonce-1');
    expect(
      buildLogicalTargetUri(
        TargetKind.service,
        'did:wba:example.com:services:message:e1_service',
      ),
      'anp://service/did%3Awba%3Aexample.com%3Aservices%3Amessage%3Ae1_service',
    );
  });
}
