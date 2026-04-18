import '../authentication/types.dart';

const String anpHandleServiceType = 'ANPHandleService';

enum HandleStatus { active, moved, gone }

class ParsedWbaUri {
  const ParsedWbaUri({required this.localPart, required this.domain});
  final String localPart;
  final String domain;
  String get handle => '$localPart@$domain';
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
    required this.did,
    required this.status,
    this.didDocument,
  });
  final String did;
  final HandleStatus status;
  final JsonMap? didDocument;
}

class ResolveHandleOptions {
  const ResolveHandleOptions({this.baseUrlOverride});
  final String? baseUrlOverride;
}

class BindingVerificationResult {
  const BindingVerificationResult({required this.verified, this.reason});
  final bool verified;
  final String? reason;
}
