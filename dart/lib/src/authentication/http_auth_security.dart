import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto;

import '../errors.dart';

typedef AuthClock = int Function();
int defaultAuthClock() => DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;

class HttpSignaturePolicy {
  const HttpSignaturePolicy({
    this.maxAgeSeconds = 300,
    this.futureSkewSeconds = 60,
    this.cryptoOnly = false,
  });
  final int maxAgeSeconds;
  final int futureSkewSeconds;
  final bool cryptoOnly;

  int validate(int created, int? expires, int now) {
    if (maxAgeSeconds < 1 ||
        maxAgeSeconds > 86400 ||
        futureSkewSeconds < 0 ||
        futureSkewSeconds > 86400 ||
        created < 0 ||
        created > 999999999999999 ||
        now < 0 ||
        now > 999999999999999 ||
        expires != null && (expires < created || expires > 999999999999999)) {
      throw const AnpAuthenticationException(
        'invalid HTTP signature time parameter or policy',
      );
    }
    final deadline = min(
      created + maxAgeSeconds,
      expires ?? created + maxAgeSeconds,
    );
    if (!cryptoOnly && (created > now + futureSkewSeconds || now > deadline)) {
      throw const AnpAuthenticationException(
        'HTTP signature timestamp is expired or invalid',
      );
    }
    return deadline;
  }
}

String authenticationOrigin(String raw) {
  final uri = Uri.parse(raw);
  final authority =
      RegExp(r'^[^:]+://([^/?#]*)').firstMatch(raw)?.group(1) ?? '';
  if (!const ['https', 'http'].contains(uri.scheme) ||
      uri.host.isEmpty ||
      authority.contains('@') ||
      raw.contains('#') ||
      RegExp(r'[\x00-\x20\x7f\\]').hasMatch(raw) ||
      uri.port < 1 ||
      uri.port > 65535) {
    throw const AnpAuthenticationException('invalid authentication URL');
  }
  final host = uri.host.contains(':')
      ? '[${_canonicalIPv6(uri.host)}]'
      : uri.host.toLowerCase();
  return '${uri.scheme}://$host:${uri.port}';
}

String _canonicalIPv6(String host) {
  final bytes = Uri.parseIPv6Address(host);
  final groups = List<int>.generate(
    8,
    (i) => (bytes[i * 2] << 8) | bytes[i * 2 + 1],
  );
  if (groups.take(5).every((value) => value == 0) && groups[5] == 0xffff) {
    throw const AnpAuthenticationException(
      'mapped IPv6 authentication origins are not supported',
    );
  }
  var start = -1, length = 1;
  for (var index = 0; index < 8;) {
    if (groups[index] != 0) {
      index++;
      continue;
    }
    var end = index;
    while (end < 8 && groups[end] == 0) {
      end++;
    }
    if (end - index > length) {
      start = index;
      length = end - index;
    }
    index = end;
  }
  String segment(Iterable<int> values) =>
      values.map((value) => value.toRadixString(16)).join(':');
  return start < 0
      ? segment(groups)
      : '${segment(groups.take(start))}::${segment(groups.skip(start + length))}';
}

/// Only verified facts, never tokens, request bodies, or raw signature bytes.
class HttpReplayContext {
  const HttpReplayContext({
    required this.signerDid,
    required this.verifierScope,
    required this.replayKey,
    required this.validUntil,
  });
  final String signerDid;
  final String verifierScope;
  final String replayKey;
  final int validUntil;
}

typedef HttpReplayConsumer = FutureOr<bool> Function(HttpReplayContext context);

abstract interface class HttpReplayStore {
  FutureOr<bool> consumeOnce(HttpReplayContext context);
}

String replayDigest(List<String> parts) {
  if (parts.any((part) => part.contains('\x00'))) {
    throw const AnpAuthenticationException('invalid replay scope');
  }
  return crypto.sha256.convert(utf8.encode(parts.join('\x00'))).toString();
}

/// Bounded single-isolate state, not a distributed or restart-safe store.
class MemoryHttpReplayStore implements HttpReplayStore {
  MemoryHttpReplayStore({this.capacity = 10000, AuthClock? clock})
    : clock = clock ?? defaultAuthClock {
    if (capacity < 1) throw ArgumentError.value(capacity, 'capacity');
  }
  final int capacity;
  final AuthClock clock;
  final _seen = <String, int>{};
  @override
  bool consumeOnce(HttpReplayContext context) {
    final now = clock();
    _seen.removeWhere((_, expiry) => expiry < now);
    if (context.validUntil < now || _seen.containsKey(context.replayKey)) {
      return false;
    }
    if (_seen.length >= capacity) {
      throw const AnpAuthenticationException('replay store capacity exhausted');
    }
    _seen[context.replayKey] = context.validUntil;
    return true;
  }
}

/// No timestamp/Math.random fallback if the platform CSPRNG is unavailable.
List<int> secureAuthNonceBytes() {
  final random = Random.secure();
  return List<int>.generate(16, (_) => random.nextInt(256));
}
