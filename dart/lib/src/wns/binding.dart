import '../authentication/types.dart';
import 'types.dart';
import 'validator.dart';

BindingVerificationResult verifyHandleBinding(
  String handle,
  JsonMap didDocument,
) {
  final services = extractHandleServiceFromDidDocument(didDocument);
  final normalized = normalizeHandle(handle);
  final ok = services.any(
    (service) => service.serviceEndpoint.contains(normalized.split('@').last),
  );
  return BindingVerificationResult(
    verified: ok,
    reason: ok ? null : 'no matching handle service',
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
