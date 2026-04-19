import 'dart:core';

import '../authentication/did_resolver.dart';
import '../authentication/types.dart';
import 'resolver.dart';
import 'types.dart';
import 'validator.dart';

Future<BindingVerificationResult> verifyHandleBinding(
  String handle, {
  BindingVerificationOptions options = const BindingVerificationOptions(),
}) async {
  final bareHandle = handle.replaceFirst(RegExp(r'^wba://'), '');
  late ParsedWbaUri parsed;
  try {
    parsed = validateHandle(bareHandle);
  } on Object catch (error) {
    return BindingVerificationResult(
      isValid: false,
      handle: bareHandle,
      errorMessage: error.toString(),
    );
  }
  final normalized = parsed.handle;
  late HandleResolutionDocument resolution;
  try {
    resolution = await resolveHandle(
      normalized,
      options: options.resolutionOptions,
    );
  } on Object catch (error) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      errorMessage: 'forward resolution failed: $error',
    );
  }
  if (resolution.status != HandleStatus.active) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      did: resolution.did,
      errorMessage:
          "handle status is '${resolution.status.name}', expected 'active'",
    );
  }
  if (!resolution.did.startsWith('did:wba:')) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      did: resolution.did,
      forwardVerified: true,
      errorMessage: 'DID does not use did:wba method',
    );
  }
  final didDomain = resolution.did.split(':').length > 2
      ? resolution.did.split(':')[2].toLowerCase()
      : '';
  if (didDomain != parsed.domain) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      did: resolution.did,
      forwardVerified: true,
      errorMessage:
          "domain mismatch: handle domain '${parsed.domain}' != DID domain '$didDomain'",
    );
  }
  JsonMap didDocument;
  try {
    didDocument =
        options.didDocument ??
        resolution.didDocument ??
        await resolveDidWbaDocument(resolution.did);
  } on Object catch (error) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      did: resolution.did,
      forwardVerified: true,
      errorMessage: 'failed to resolve DID document: $error',
    );
  }
  final reverseVerified = extractHandleServiceFromDidDocument(didDocument).any(
    (service) =>
        _matchesHandleServiceDomain(service.serviceEndpoint, parsed.domain),
  );
  if (!reverseVerified) {
    return BindingVerificationResult(
      isValid: false,
      handle: normalized,
      did: resolution.did,
      forwardVerified: true,
      errorMessage:
          "DID Document does not contain an $anpHandleServiceType entry whose HTTPS domain matches '${parsed.domain}'",
    );
  }
  return BindingVerificationResult(
    isValid: true,
    handle: normalized,
    did: resolution.did,
    forwardVerified: true,
    reverseVerified: true,
  );
}

HandleServiceEntry buildHandleServiceEntry(
  String did,
  String localPart,
  String domain,
) => HandleServiceEntry(
  id: '$did#handle',
  type: anpHandleServiceType,
  serviceEndpoint: buildResolutionUrl(localPart, domain),
);

List<HandleServiceEntry> extractHandleServiceFromDidDocument(
  JsonMap didDocument,
) {
  final services = didDocument['service'];
  if (services is! List) return const <HandleServiceEntry>[];
  return [
    for (final service in services)
      if (service is Map && service['type'] == anpHandleServiceType)
        HandleServiceEntry(
          id: service['id']?.toString() ?? '',
          type: service['type']?.toString() ?? '',
          serviceEndpoint: service['serviceEndpoint']?.toString() ?? '',
        ),
  ];
}

bool _matchesHandleServiceDomain(
  String serviceEndpoint,
  String expectedDomain,
) {
  final uri = Uri.tryParse(serviceEndpoint);
  return uri != null &&
      uri.scheme.toLowerCase() == 'https' &&
      uri.host.toLowerCase() == expectedDomain.toLowerCase();
}
