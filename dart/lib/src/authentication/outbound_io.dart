import 'dart:async';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'outbound_policy.dart';

/// TLS still uses the original URI hostname. Only the TCP dial uses checked IPs.
http.Client createPublicClient(
  Duration timeout, {
  bool trustedOverride = false,
}) {
  final client = HttpClient();
  client.findProxy = (_) => 'DIRECT';
  client.connectionTimeout = timeout;
  client.idleTimeout = const Duration(seconds: 10);
  client.maxConnectionsPerHost = 8;
  client.connectionFactory = (uri, proxyHost, proxyPort) async {
    if (proxyHost != null || proxyPort != null) {
      throw const SocketException('ambient proxy rejected');
    }
    if (trustedOverride) return Socket.startConnect(uri.host, uri.port);
    return connectChecked(uri, timeout);
  };
  return IOClient(client);
}

/// Internal injectable connection boundary. Production defaults resolve once and
/// pass InternetAddress objects (not hostnames) to the socket connector.
Future<ConnectionTask<Socket>> connectChecked(
  Uri uri,
  Duration timeout, {
  Future<List<InternetAddress>> Function(String)? lookup,
  Future<ConnectionTask<Socket>> Function(InternetAddress, int)? connectSocket,
}) async {
  final addresses = await (lookup ?? InternetAddress.lookup)(
    uri.host,
  ).timeout(timeout);
  if (addresses.isEmpty ||
      addresses.any((address) => !isPublicAddressBytes(address.rawAddress))) {
    throw const SocketException('ANP DNS resolved to a non-public address');
  }
  final pending = <ConnectionTask<Socket>>[];
  var cancelled = false;
  Future<Socket> connect() async {
    Object? last;
    for (final address in addresses.take(16)) {
      if (cancelled) throw const SocketException('ANP connection cancelled');
      final task = await (connectSocket ?? Socket.startConnect)(
        address,
        uri.port,
      );
      pending.add(task);
      if (cancelled) {
        task.cancel();
        throw const SocketException('ANP connection cancelled');
      }
      try {
        return await task.socket.timeout(const Duration(seconds: 1));
      } catch (error) {
        last = error;
        task.cancel();
      }
    }
    throw last ?? const SocketException('ANP connection failed');
  }

  return ConnectionTask.fromSocket(connect(), () {
    cancelled = true;
    for (final task in pending) {
      task.cancel();
    }
  });
}
