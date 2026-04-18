import 'package:anp/anp.dart';

void main() {
  final bundle = createDidWbaDocument(
    'example.com',
    options: const DidDocumentOptions(
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.e1,
    ),
  );
  print(bundle.didDocument['id']);
}
