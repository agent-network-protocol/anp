import '../authentication/types.dart';

const String anpHandleServiceType = 'ANPHandleService';

enum HandleStatus { active, moved, gone }

class ParsedWbaUri {
  const ParsedWbaUri({
    required this.localPart,
    required this.domain,
    String? originalUri,
  }) : originalUri = originalUri ?? 'wba://$localPart.$domain';

  final String localPart;
  final String domain;
  final String originalUri;
  String get handle => '$localPart.$domain';
  String get uri => 'wba://$handle';
}

class HandleServiceEntry {
  const HandleServiceEntry({
    required this.id,
    required this.type,
    required this.serviceEndpoint,
  });
  final String id;
  final String type;
  final String serviceEndpoint;
  JsonMap toJson() => {
    'id': id,
    'type': type,
    'serviceEndpoint': serviceEndpoint,
  };
}

class HandleResolutionDocument {
  const HandleResolutionDocument({
    required this.handle,
    required this.did,
    required this.status,
    this.didDocument,
  });
  final String handle;
  final String did;
  final HandleStatus status;
  final JsonMap? didDocument;
}

class ResolveHandleOptions {
  const ResolveHandleOptions({
    this.baseUrlOverride,
    this.verifySsl = true,
    this.timeout = const Duration(seconds: 10),
  });
  final String? baseUrlOverride;
  final bool verifySsl;
  final Duration timeout;
}

class BindingVerificationOptions {
  const BindingVerificationOptions({
    this.resolutionOptions = const ResolveHandleOptions(),
    this.didDocument,
  });
  final ResolveHandleOptions resolutionOptions;
  final JsonMap? didDocument;
}

class BindingVerificationResult {
  const BindingVerificationResult({
    required this.isValid,
    required this.handle,
    this.did,
    this.forwardVerified = false,
    this.reverseVerified = false,
    this.errorMessage,
  });

  final bool isValid;
  final String handle;
  final String? did;
  final bool forwardVerified;
  final bool reverseVerified;
  final String? errorMessage;

  bool get verified => isValid;
  String? get reason => errorMessage;
}
