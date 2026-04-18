import 'package:anp/anp.dart';

void main() {
  final parsed = validateHandle('alice@example.com');
  final uri = buildWbaUri(parsed.localPart, parsed.domain);
  final service = buildHandleServiceEntry(
    'did:wba:example.com:user:alice',
    parsed.localPart,
    parsed.domain,
  );
  print('$uri -> ${service.serviceEndpoint}');
}
