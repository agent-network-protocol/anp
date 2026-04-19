import 'package:anp/anp.dart';

Future<void> main() async {
  final bundle = createDidWbaDocument('example.com');
  final key = bundle.keys[vmKeyAuth]!.privateKey;
  final body = '{"item":"book"}'.codeUnits;
  final headers = await generateHttpSignatureHeaders(
    didDocument: bundle.didDocument,
    requestMethod: 'POST',
    requestUrl: 'https://api.example.com/orders',
    privateKey: key,
    body: body,
  );
  await verifyHttpMessageSignature(
    didDocument: bundle.didDocument,
    requestMethod: 'POST',
    requestUrl: 'https://api.example.com/orders',
    headers: headers,
    body: body,
  );
  print(true);
}
