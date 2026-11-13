import 'package:http/http.dart' as http;

http.Client createPublicClient(
  Duration timeout, {
  bool trustedOverride = false,
}) => throw UnsupportedError(
  'A checked IO transport is required; browser hosts must explicitly supply a trusted client',
);
