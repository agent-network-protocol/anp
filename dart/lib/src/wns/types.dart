import '../authentication/types.dart';

const String anpHandleServiceType = 'ANPHandleService';

enum HandleStatus { active, suspended, revoked, moved, gone }

enum SubjectType {
  person,
  agent,
  group,
  organization,
  service,
  application,
  unknown,
}

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
    this.updated,
    this.versionId,
    this.ttl,
    this.profile,
    this.didDocument,
  });
  final String handle;
  final String did;
  final HandleStatus status;
  final String? updated;
  final String? versionId;
  final int? ttl;
  final DidSubjectProfile? profile;
  final JsonMap? didDocument;

  JsonMap toJson() => {
    'handle': handle,
    'did': did,
    'status': status.name,
    if (updated != null) 'updated': updated,
    if (versionId != null) 'versionId': versionId,
    if (ttl != null) 'ttl': ttl,
    if (profile != null) 'profile': profile!.toJson(),
    if (didDocument != null) 'didDocument': didDocument,
  };
}

class DidSubjectProfile {
  const DidSubjectProfile({
    this.type = 'DIDSubjectProfile',
    required this.subjectDid,
    this.subjectType = SubjectType.unknown,
    this.handle,
    this.displayName,
    this.description,
    this.avatarUri,
    this.profileUri,
    this.discoverability,
    this.labels,
    this.updated,
    this.versionId,
    this.ttl,
    this.proof,
  });

  final String type;
  final String subjectDid;
  final SubjectType subjectType;
  final String? handle;
  final String? displayName;
  final String? description;
  final String? avatarUri;
  final String? profileUri;
  final String? discoverability;
  final JsonMap? labels;
  final String? updated;
  final String? versionId;
  final int? ttl;
  final JsonMap? proof;

  factory DidSubjectProfile.fromJson(JsonMap json) => DidSubjectProfile(
    type: json['type']?.toString() ?? 'DIDSubjectProfile',
    subjectDid: json['subject_did']?.toString() ?? '',
    subjectType: _parseSubjectType(json['subject_type']),
    handle: json['handle']?.toString(),
    displayName: json['display_name']?.toString(),
    description: json['description']?.toString(),
    avatarUri: json['avatar_uri']?.toString(),
    profileUri: json['profile_uri']?.toString(),
    discoverability: json['discoverability']?.toString(),
    labels: json['labels'] is Map
        ? Map<String, Object?>.from(
            (json['labels'] as Map).cast<String, Object?>(),
          )
        : null,
    updated: json['updated']?.toString(),
    versionId: json['versionId']?.toString(),
    ttl: json['ttl'] is int ? json['ttl'] as int : null,
    proof: json['proof'] is Map
        ? Map<String, Object?>.from(
            (json['proof'] as Map).cast<String, Object?>(),
          )
        : null,
  );

  JsonMap toJson() => {
    'type': type,
    'subject_did': subjectDid,
    'subject_type': subjectType.name,
    if (handle != null) 'handle': handle,
    if (displayName != null) 'display_name': displayName,
    if (description != null) 'description': description,
    if (avatarUri != null) 'avatar_uri': avatarUri,
    if (profileUri != null) 'profile_uri': profileUri,
    if (discoverability != null) 'discoverability': discoverability,
    if (labels != null) 'labels': labels,
    if (updated != null) 'updated': updated,
    if (versionId != null) 'versionId': versionId,
    if (ttl != null) 'ttl': ttl,
    if (proof != null) 'proof': proof,
  };
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

SubjectType _parseSubjectType(Object? value) {
  if (value == null) return SubjectType.unknown;
  final normalized = value.toString().toLowerCase();
  for (final type in SubjectType.values) {
    if (type.name == normalized) return type;
  }
  return SubjectType.unknown;
}
