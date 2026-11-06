// Portions derived from ds-harness-remote (https://github.com/liguobao/ds-harness-remote), MIT, Copyright (c) 2026 DSH Remote contributors. See THIRD_PARTY_NOTICES.md.
// Local Direct wire format (upstream packages/protocol/src/local.ts and
// packages/crypto/src/local.ts): control frames, the pairing link carried by
// the Host's QR code, private-network address checks and the pairing proof.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;

import '../protocol/control.dart' show ProtocolError;
import '../util/bytes.dart';

const int localDirectVersion = 1;
const String localDirectPath = '/dsh-remote/local/v1';
const int localDirectDefaultPort = 47821;

/// Frames before the secure channel is ready are small; anything larger is hostile.
const int localMaxPreauthFrameBytes = 8 * 1024;
const int localMaxAddresses = 8;
const int localPairingCodeBytes = 16;

const int _maxNameBytes = 128;

final RegExp _ulid = RegExp(r'^[0-9A-HJKMNP-TV-Z]{26}$', caseSensitive: false);
final RegExp _uuid = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
  caseSensitive: false,
);
final RegExp _platform = RegExp(r'^[a-z0-9][a-z0-9._-]*$');
final RegExp _version = RegExp(r'^[0-9A-Za-z.+_-]+$');
final RegExp _capability = RegExp(r'^[a-z0-9][a-z0-9._-]*$');
final RegExp _errorCode = RegExp(r'^[A-Z][A-Z0-9_]*$');
final RegExp _handshakeData = RegExp(r'^[A-Za-z0-9_-]+$');
final RegExp _control = RegExp(r'[\u0000-\u001f\u007f]');

bool isLocalDeviceId(Object? value) => value is String && (_ulid.hasMatch(value) || _uuid.hasMatch(value));

bool isLocalDisplayName(Object? value) {
  if (value is! String) return false;
  final bytes = utf8.encode(value).length;
  return bytes >= 1 && bytes <= _maxNameBytes && value.trim().isNotEmpty && !_control.hasMatch(value);
}

/// `local.hello`: who this Client is and whether it connects or pairs.
class LocalHello {
  const LocalHello({
    required this.clientDeviceId,
    required this.clientIdentityKey,
    required this.name,
    required this.platform,
    required this.intent,
    this.clientVersion,
    this.capabilities = const [],
  });

  final String clientDeviceId;
  final String clientIdentityKey;
  final String name;
  final String platform;
  final String? clientVersion;
  final List<String> capabilities;

  /// `connect` (already paired) or `pair`.
  final LocalIntent intent;

  String encode() {
    if (!isLocalDeviceId(clientDeviceId) || !identityKeyPattern.hasMatch(clientIdentityKey)) {
      throw ArgumentError('local.hello needs a ULID/UUID device id and an X25519 identity key.');
    }
    if (!isLocalDisplayName(name) || platform.length > 64 || !_platform.hasMatch(platform)) {
      throw ArgumentError('local.hello name or platform is invalid.');
    }
    final version = clientVersion;
    if (version != null && (version.isEmpty || version.length > 64 || !_version.hasMatch(version))) {
      throw ArgumentError('local.hello clientVersion is invalid.');
    }
    return _encodeControl('local.hello', {
      'clientDeviceId': clientDeviceId,
      'clientIdentityKey': clientIdentityKey,
      'name': name,
      'platform': platform,
      'clientVersion': ?version,
      'capabilities': capabilities,
      'intent': intent.name,
    });
  }
}

enum LocalIntent { connect, pair }

/// `local.hello.ack`: the Host's identity and the Host-generated connection id.
class LocalHelloAck {
  const LocalHelloAck({
    required this.hostDeviceId,
    required this.hostIdentityKey,
    required this.name,
    required this.connectionId,
    this.hostVersion,
  });

  final String hostDeviceId;
  final String hostIdentityKey;
  final String name;
  final String connectionId;
  final String? hostVersion;
}

/// A decoded control frame from the Host.
sealed class LocalControlFrame {
  const LocalControlFrame();
}

final class LocalAckFrame extends LocalControlFrame {
  const LocalAckFrame(this.ack);
  final LocalHelloAck ack;
}

final class LocalHandshakeFrame extends LocalControlFrame {
  const LocalHandshakeFrame(this.connectionId, this.step, this.data);
  final String connectionId;
  final int step;
  final Uint8List data;
}

final class LocalErrorFrame extends LocalControlFrame {
  const LocalErrorFrame(this.code, this.message);
  final String code;
  final String message;
}

String encodeLocalHandshake(String connectionId, int step, Uint8List data) =>
    _encodeControl('secure.handshake', {'connectionId': connectionId, 'step': step, 'data': toBase64Url(data)});

String _encodeControl(String type, Map<String, Object?> payload) {
  final text = jsonEncode({'v': localDirectVersion, 'type': type, 'payload': payload});
  if (utf8.encode(text).length > localMaxPreauthFrameBytes) {
    throw const ProtocolError('Local control frame exceeds its limit.', 'FRAME_TOO_LARGE');
  }
  return text;
}

/// Decodes a Host control frame, rejecting unknown fields, repeated keys and
/// anything a Client never receives (`local.hello`). Throws [ProtocolError].
LocalControlFrame decodeLocalControlFrame(String text) {
  if (utf8.encode(text).length > localMaxPreauthFrameBytes) {
    throw const ProtocolError('Local control frame exceeds its limit.', 'FRAME_TOO_LARGE');
  }
  final (type, payload) = _envelope(text);
  switch (type) {
    case 'local.hello.ack':
      _onlyKeys(payload, const {
        'hostDeviceId',
        'hostIdentityKey',
        'name',
        'connectionId',
        'capabilities',
        'hostVersion',
      });
      final hostDeviceId = payload['hostDeviceId'];
      final hostIdentityKey = payload['hostIdentityKey'];
      final name = payload['name'];
      final connectionId = payload['connectionId'];
      final capabilities = payload['capabilities'];
      final hostVersion = payload['hostVersion'];
      if (!isLocalDeviceId(hostDeviceId) ||
          !isLocalDeviceId(connectionId) ||
          hostIdentityKey is! String ||
          !identityKeyPattern.hasMatch(hostIdentityKey) ||
          !isLocalDisplayName(name) ||
          !_validCapabilities(capabilities) ||
          (hostVersion != null &&
              (hostVersion is! String ||
                  hostVersion.isEmpty ||
                  hostVersion.length > 64 ||
                  !_version.hasMatch(hostVersion)))) {
        throw const ProtocolError('local.hello.ack is invalid.');
      }
      return LocalAckFrame(
        LocalHelloAck(
          hostDeviceId: hostDeviceId! as String,
          hostIdentityKey: hostIdentityKey,
          name: name! as String,
          connectionId: connectionId! as String,
          hostVersion: hostVersion as String?,
        ),
      );
    case 'secure.handshake':
      _onlyKeys(payload, const {'connectionId', 'step', 'data'});
      final connectionId = payload['connectionId'];
      final step = payload['step'];
      final data = payload['data'];
      if (!isLocalDeviceId(connectionId) ||
          (step != 1 && step != 2) ||
          data is! String ||
          data.isEmpty ||
          data.length > 4096 ||
          !_handshakeData.hasMatch(data) ||
          data.length % 4 == 1) {
        throw const ProtocolError('secure.handshake is invalid.');
      }
      return LocalHandshakeFrame(connectionId! as String, step! as int, fromBase64Url(data));
    case 'local.error':
      _onlyKeys(payload, const {'code', 'message'});
      final code = payload['code'];
      final message = payload['message'];
      if (code is! String ||
          code.isEmpty ||
          code.length > 64 ||
          !_errorCode.hasMatch(code) ||
          message is! String ||
          message.length > 512) {
        throw const ProtocolError('local.error is invalid.');
      }
      return LocalErrorFrame(code, message);
    default:
      throw const ProtocolError('Unexpected Local Direct control frame.');
  }
}

/// `local.pair.prove`, the first Noise transport plaintext of a pairing connection.
Uint8List encodeLocalPairProve(String proof) => Uint8List.fromList(
  utf8.encode(
    jsonEncode({
      'v': localDirectVersion,
      'type': 'local.pair.prove',
      'payload': {'proof': proof},
    }),
  ),
);

/// Decodes the Host's `local.pair.ok` and returns its `pairingId`. Throws [ProtocolError].
String decodeLocalPairOk(Uint8List data) {
  if (data.length > localMaxPreauthFrameBytes) throw const ProtocolError('Local pairing frame exceeds its limit.');
  final String text;
  try {
    text = utf8.decode(data);
  } on FormatException {
    throw const ProtocolError('Local pairing frame is not UTF-8.');
  }
  final (type, payload) = _envelope(text);
  if (type != 'local.pair.ok') throw const ProtocolError('Expected local.pair.ok.');
  _onlyKeys(payload, const {'pairingId'});
  final pairingId = payload['pairingId'];
  if (!isLocalDeviceId(pairingId)) throw const ProtocolError('local.pair.ok is invalid.');
  return pairingId! as String;
}

(String, JsonMap) _envelope(String text) {
  final Object? value;
  try {
    value = decodeWireJson(text);
  } on FormatException {
    throw const ProtocolError('Local frame is not valid JSON.');
  }
  final frame = asMap(value);
  if (frame == null) throw const ProtocolError('Local frame is not an object.');
  _onlyKeys(frame, const {'v', 'type', 'payload'});
  if (frame['v'] != localDirectVersion) {
    throw const ProtocolError('Unsupported Local Direct version.', 'UNSUPPORTED_VERSION');
  }
  final type = frame['type'];
  final payload = asMap(frame['payload']);
  if (type is! String || payload == null) throw const ProtocolError('Local frame has no type or payload.');
  return (type, payload);
}

void _onlyKeys(JsonMap map, Set<String> allowed) {
  for (final key in map.keys) {
    if (!allowed.contains(key)) throw ProtocolError('Unknown field "$key" in a Local Direct frame.');
  }
}

bool _validCapabilities(Object? value) {
  if (value is! List || value.length > 128) return false;
  final seen = <String>{};
  for (final item in value) {
    if (item is! String || item.isEmpty || item.length > 128 || !_capability.hasMatch(item) || !seen.add(item)) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Pairing proof

final Uint8List _proofLabel = Uint8List.fromList(utf8.encode('DSH-REMOTE-LOCAL\u0000pair-proof\u0000v=1\u0000'));

/// `Base64URL(HMAC-SHA256(pairingCode, "DSH-REMOTE-LOCAL\0pair-proof\0v=1\0" || handshakeHash))`:
/// proves the Client knows the code, bound to one handshake. The code itself
/// never goes on the wire.
String createLocalPairingProof(String pairingCode, List<int> handshakeHash) {
  final key = _requirePairingCode(pairingCode);
  try {
    return toBase64Url(hashes.Hmac(hashes.sha256, key).convert(concatBytes([_proofLabel, handshakeHash])).bytes);
  } finally {
    key.fillRange(0, key.length, 0);
  }
}

bool isLocalPairingCode(String value) {
  if (value.length != 22 || !isCanonicalBase64Url(value)) return false;
  try {
    return fromBase64Url(value).length == localPairingCodeBytes;
  } on FormatException {
    return false;
  }
}

Uint8List _requirePairingCode(String value) {
  if (!isLocalPairingCode(value)) {
    throw ArgumentError('Pairing code must be 16 bytes of canonical base64url.');
  }
  return fromBase64Url(value);
}

// ---------------------------------------------------------------------------
// Pairing link

/// What a Host pairing QR code carries:
/// `dshremote://local-pair?v=1&id=<hostDeviceId>&k=<hostIdentityKey>&a=<addr>[,<addr>…]&c=<pairingCode>[&n=<name>]`.
class LocalPairingLink {
  LocalPairingLink({
    required this.hostDeviceId,
    required this.hostIdentityKey,
    required List<LocalAddress> addresses,
    required this.pairingCode,
    this.name,
  }) : addresses = List.unmodifiable(addresses);

  final String hostDeviceId;
  final String hostIdentityKey;
  final List<LocalAddress> addresses;
  final String pairingCode;
  final String? name;

  static const _fields = {'v', 'id', 'k', 'a', 'c', 'n'};

  /// Parses a scanned link. Only private-network IP literals are accepted;
  /// unknown or repeated fields are refused. Throws [FormatException].
  static LocalPairingLink parse(String value) {
    final Uri uri;
    try {
      uri = Uri.parse(value.trim());
    } on FormatException {
      throw const FormatException('Pairing link is not a URL.');
    }
    if (uri.scheme != 'dshremote' ||
        uri.host != 'local-pair' ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        (uri.path.isNotEmpty && uri.path != '/') ||
        uri.hasFragment) {
      throw const FormatException('Pairing link has the wrong shape.');
    }
    final Map<String, List<String>> params;
    try {
      params = uri.queryParametersAll;
    } on Object {
      throw const FormatException('Pairing link query is malformed.');
    }
    for (final MapEntry(:key, value: values) in params.entries) {
      if (!_fields.contains(key) || values.length != 1) {
        throw const FormatException('Pairing link has unknown or repeated fields.');
      }
    }
    String? field(String key) => params[key]?.single;
    if (field('v') != '$localDirectVersion') throw const FormatException('Pairing link version is not supported.');
    final id = field('id') ?? '';
    final key = field('k') ?? '';
    final code = field('c') ?? '';
    final name = field('n');
    final rawAddresses = (field('a') ?? '').split(',').where((item) => item.isNotEmpty).toList();
    if (!isLocalDeviceId(id)) throw const FormatException('Pairing link Host id is invalid.');
    if (!identityKeyPattern.hasMatch(key)) throw const FormatException('Pairing link Host key is invalid.');
    if (!isLocalPairingCode(code)) throw const FormatException('Pairing link code is invalid.');
    if (rawAddresses.isEmpty || rawAddresses.length > localMaxAddresses) {
      throw const FormatException('Pairing link must carry 1 to 8 addresses.');
    }
    if (name != null && !isLocalDisplayName(name)) throw const FormatException('Pairing link name is invalid.');
    return LocalPairingLink(
      hostDeviceId: id,
      hostIdentityKey: key,
      addresses: rawAddresses.map(LocalAddress.parse).toList(),
      pairingCode: code,
      name: name,
    );
  }

  static LocalPairingLink? tryParse(String value) {
    try {
      return parse(value);
    } on FormatException {
      return null;
    }
  }
}

/// A private-network IP literal and port (`192.168.1.10:47821`, `[fd00::1]:47821`).
class LocalAddress {
  const LocalAddress._(this.host, this.port);

  /// Lower-case IP literal, without brackets.
  final String host;
  final int port;

  static final RegExp _pattern = RegExp(r'^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)):(\d{1,5})$');

  /// Parses `host:port`; only private-network IP literals pass. Throws [FormatException].
  static LocalAddress parse(String value) {
    final match = _pattern.firstMatch(value.trim());
    if (match == null) throw const FormatException('Local address must be an IP literal with a port.');
    final host = (match.group(1) ?? match.group(2))!.toLowerCase();
    final port = int.parse(match.group(3)!);
    if (port < 1 || port > 65535) throw const FormatException('Local address port is invalid.');
    if (!isPrivateNetworkAddress(host)) throw const FormatException('Local address must be a private-network address.');
    return LocalAddress._(host, port);
  }

  /// [parse] for manual input: a bare IP gets [localDirectDefaultPort].
  static LocalAddress parseInput(String value) {
    final text = value.trim();
    if (_parseIpv4(text) != null) return parse('$text:$localDirectDefaultPort');
    final bare = text.startsWith('[') && text.endsWith(']') ? text.substring(1, text.length - 1) : text;
    if (_parseIpv6(bare.toLowerCase()) != null) return parse('[$bare]:$localDirectDefaultPort');
    return parse(text);
  }

  static LocalAddress? tryParse(String value) {
    try {
      return parse(value);
    } on FormatException {
      return null;
    }
  }

  /// `ws://<addr>/dsh-remote/local/v1`.
  Uri get webSocketUri => Uri.parse('ws://$this$localDirectPath');

  @override
  String toString() => host.contains(':') ? '[$host]:$port' : '$host:$port';

  @override
  bool operator ==(Object other) => other is LocalAddress && other.host == host && other.port == port;

  @override
  int get hashCode => Object.hash(host, port);
}

/// Loopback, RFC 1918, link-local, CGNAT (Tailscale), IPv6 ULA (common for
/// WireGuard) and IPv6 link-local/loopback. Public addresses are refused.
bool isPrivateNetworkAddress(String host) {
  final v4 = _parseIpv4(host);
  if (v4 != null) {
    final [a, b, ...] = v4;
    return a == 10 ||
        a == 127 ||
        (a == 172 && b >= 16 && b <= 31) ||
        (a == 192 && b == 168) ||
        (a == 169 && b == 254) ||
        (a == 100 && b >= 64 && b <= 127);
  }
  final v6 = _parseIpv6(host);
  if (v6 == null) return false;
  var loopback = true;
  for (var i = 0; i < 8; i++) {
    if (v6[i] != (i == 7 ? 1 : 0)) loopback = false;
  }
  if (loopback) return true;
  if (v6.sublist(0, 5).every((word) => word == 0) && v6[5] == 0xffff) {
    return isPrivateNetworkAddress('${v6[6] >> 8}.${v6[6] & 255}.${v6[7] >> 8}.${v6[7] & 255}');
  }
  return (v6[0] & 0xfe00) == 0xfc00 || (v6[0] & 0xffc0) == 0xfe80;
}

final RegExp _octet = RegExp(r'^(0|[1-9]\d{0,2})$');

List<int>? _parseIpv4(String value) {
  final parts = value.split('.');
  if (parts.length != 4 || parts.any((part) => !_octet.hasMatch(part))) return null;
  final octets = parts.map(int.parse).toList();
  return octets.every((octet) => octet <= 255) ? octets : null;
}

final RegExp _ipv6Chars = RegExp(r'^[0-9a-f:.]+$', caseSensitive: false);
final RegExp _tailV4 = RegExp(r'(\d+\.\d+\.\d+\.\d+)$');
final RegExp _hextet = RegExp(r'^[0-9a-f]{1,4}$', caseSensitive: false);

List<int>? _parseIpv6(String value) {
  if (!_ipv6Chars.hasMatch(value) || value.split('::').length > 2) return null;
  var text = value;
  var tail = <int>[];
  final tailMatch = _tailV4.firstMatch(text);
  if (tailMatch != null) {
    final v4 = _parseIpv4(tailMatch.group(1)!);
    if (v4 == null) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    text = text.substring(0, text.length - tailMatch.group(1)!.length);
    if (text.endsWith(':') && !text.endsWith('::')) text = text.substring(0, text.length - 1);
  }
  final halves = text.split('::');
  List<int>? parse(String part) {
    if (part.isEmpty) return [];
    final items = part.split(':');
    if (items.any((item) => !_hextet.hasMatch(item))) return null;
    return [for (final item in items) int.parse(item, radix: 16)];
  }

  final left = parse(halves[0]);
  final right = halves.length == 2 ? parse(halves[1]) : <int>[];
  if (left == null || right == null) return null;
  final total = left.length + right.length + tail.length;
  if (halves.length == 1) {
    if (total != 8) return null;
    return [...left, ...tail];
  }
  if (total > 7) return null;
  return [...left, ...List<int>.filled(8 - total, 0), ...right, ...tail];
}
