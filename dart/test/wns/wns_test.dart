import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('validates and builds WBA URI', () {
    final parsed = validateHandle('Alice@Example.COM');
    expect(parsed.handle, 'alice@example.com');
    expect(
      buildWbaUri(parsed.localPart, parsed.domain),
      'wba://alice@example.com',
    );
  });

  test('extracts handle service', () {
    final service = buildHandleServiceEntry(
      'did:wba:example.com:user:alice',
      'alice',
      'example.com',
    );
    final services = extractHandleServiceFromDidDocument({
      'service': [service.toJson()],
    });
    expect(services.single.type, anpHandleServiceType);
  });
}
