/// Base exception for ANP Dart SDK failures.
class AnpException implements Exception {
  const AnpException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() => cause == null
      ? 'AnpException: $message'
      : 'AnpException: $message ($cause)';
}

class AnpCodecException extends AnpException {
  const AnpCodecException(super.message, {super.cause});
}

class AnpCryptoException extends AnpException {
  const AnpCryptoException(super.message, {super.cause});
}

class AnpAuthenticationException extends AnpException {
  const AnpAuthenticationException(super.message, {super.cause});
}

class AnpProofException extends AnpException {
  const AnpProofException(super.message, {super.cause});
}

class AnpNetworkException extends AnpException {
  const AnpNetworkException(super.message, {super.cause});
}

class AnpWnsException extends AnpException {
  const AnpWnsException(super.message, {super.cause});
}
