// Local Direct: golden vectors (fixtures/local-noise-ik.json is copied verbatim
// from ds-harness-remote `fixtures/crypto/local-v1/noise-ik.json`, MIT,
// synthetic keys), pairing links, and pairing / connecting against a fake Host.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dsh_remote/dsh_remote.dart';
import 'package:dsh_remote/src/util/bytes.dart';
import 'package:test/test.dart';

Map<String, Object?> _m(Object? value) => (value! as Map).cast<String, Object?>();

Map<String, Object?> _vector() {
  final json = _m(jsonDecode(File('test/fixtures/local-noise-ik.json').readAsStringSync()));
  expect(json['fixtureFormat'], 'dsh-remote.local-noise-vectors');
  expect(json['suite'], noiseIkProtocol);
  return _m((json['vectors']! as List).single);
}

const _hostId = '0198f3a2-6b1c-7d2e-8f30-4a5b6c7d8e9f';
const _code = 'wMHCw8TFxsfIycrLzM3Ozw';

String _link({String? key, String addresses = '127.0.0.1:47821', String extra = ''}) {
  final k = key ?? X25519KeyPair.generate().publicKeyBase64Url;
  return 'dshremote://local-pair?v=1&id=$_hostId&k=$k&a=${Uri.encodeQueryComponent(addresses)}&c=$_code$extra';
}

void main() {
  group('Local Direct golden vectors (fixtures/crypto/local-v1)', () {
    test('prologue, handshake, handshake hash, transport and pairing proof match TypeScript', () {
      final vector = _vector();
      final statics = _m(vector['staticKeys']);
      final ini = _m(statics['initiator']);
      final res = _m(statics['responder']);
      final eph = _m(vector['ephemeralPrivateKeys']);
      final prologue = _m(vector['prologue']);
      final bytes = createLocalNoisePrologue(
        prologue['connectionId']! as String,
        prologue['hostDeviceId']! as String,
        prologue['clientDeviceId']! as String,
      );
      expect(toBase64Url(bytes), prologue['bytes']);

      final initiator = NoiseIkSession(
        role: NoiseRole.initiator,
        localPrivateKey: ini['privateKey']! as String,
        localPublicKey: ini['publicKey']! as String,
        remotePublicKey: res['publicKey']! as String,
        prologue: bytes,
        ephemeralPrivateKey: fromBase64Url(eph['initiator']! as String),
      );
      final responder = NoiseIkSession(
        role: NoiseRole.responder,
        localPrivateKey: res['privateKey']! as String,
        localPublicKey: res['publicKey']! as String,
        remotePublicKey: ini['publicKey']! as String,
        prologue: bytes,
        ephemeralPrivateKey: fromBase64Url(eph['responder']! as String),
      );
      expect(() => initiator.handshakeHash, throwsA(isA<NoiseSessionError>()));

      final handshake = _m(vector['handshake']);
      final message1 = initiator.writeHandshake();
      expect(toBase64Url(message1), handshake['message1']);
      responder.readHandshake(message1);
      final message2 = responder.writeHandshake();
      expect(toBase64Url(message2), handshake['message2']);
      initiator.readHandshake(message2);

      expect(toBase64Url(initiator.handshakeHash), vector['handshakeHash']);
      expect(toBase64Url(responder.handshakeHash), vector['handshakeHash']);

      final transport = _m(vector['transport']);
      expect(transport['sender'], 'initiator');
      final ciphertext = initiator.encrypt(fromBase64Url(transport['plaintext']! as String));
      expect(toBase64Url(ciphertext), transport['ciphertext']);
      expect(toBase64Url(responder.decrypt(ciphertext)), transport['plaintext']);

      final pairing = _m(vector['pairing']);
      expect(createLocalPairingProof(pairing['code']! as String, initiator.handshakeHash), pairing['proof']);
    });

    test('the account prologue differs from the Local Direct one', () {
      expect(
        toBase64Url(createNoisePrologue('c', 'h', 'd')),
        isNot(toBase64Url(createLocalNoisePrologue('c', 'h', 'd'))),
      );
      expect(() => createLocalNoisePrologue('c\u0000', 'h', 'd'), throwsArgumentError);
    });

    test('the pairing proof needs a canonical 16-byte code', () {
      final hash = Uint8List(32);
      expect(() => createLocalPairingProof('short', hash), throwsArgumentError);
      // Same bytes, non-canonical trailing bits.
      expect(() => createLocalPairingProof('wMHCw8TFxsfIycrLzM3Oz1', hash), throwsArgumentError);
    });
  });

  group('pairing link', () {
    test('parses every field and keeps private addresses in order', () {
      final key = X25519KeyPair.generate().publicKeyBase64Url;
      final link = LocalPairingLink.parse(
        _link(key: key, addresses: '192.168.1.10:47821,[FD00::1]:47821,100.64.0.2:9000', extra: '&n=Work+PC'),
      );
      expect(link.hostDeviceId, _hostId);
      expect(link.hostIdentityKey, key);
      expect(link.pairingCode, _code);
      expect(link.name, 'Work PC');
      expect(link.addresses.map((a) => '$a'), ['192.168.1.10:47821', '[fd00::1]:47821', '100.64.0.2:9000']);
      expect(link.addresses.first.webSocketUri.toString(), 'ws://192.168.1.10:47821/dsh-remote/local/v1');
    });

    test('refuses unknown, repeated or missing fields and other shapes', () {
      final key = X25519KeyPair.generate().publicKeyBase64Url;
      for (final bad in [
        _link(key: key, extra: '&x=1'),
        _link(key: key, extra: '&c=$_code'),
        _link(key: key).replaceFirst('v=1', 'v=2'),
        _link(key: key).replaceFirst('&c=$_code', ''),
        _link(key: key).replaceFirst('dshremote://local-pair', 'dshremote://other'),
        _link(key: key).replaceFirst('dshremote:', 'https:'),
        '${_link(key: key)}#frag',
        _link(key: key, addresses: ''),
        _link(key: 'not-a-key'),
        _link(key: key).replaceFirst(_hostId, 'host'),
        _link(key: key, addresses: List.filled(9, '10.0.0.1:1').join(',')),
      ]) {
        expect(() => LocalPairingLink.parse(bad), throwsFormatException, reason: bad);
      }
    });

    test('accepts only private IP literals with a port', () {
      for (final bad in ['dsh.local:47821', '8.8.8.8:47821', '[2001:db8::1]:47821', '10.0.0.1', '010.0.0.1:1']) {
        expect(() => LocalPairingLink.parse(_link(addresses: bad)), throwsFormatException, reason: bad);
      }
      for (final good in [
        '10.1.2.3:1',
        '172.31.0.1:2',
        '169.254.1.1:3',
        '127.0.0.1:4',
        '[::1]:5',
        '[fe80::1]:6',
        '[::ffff:192.168.0.1]:7',
      ]) {
        expect(LocalAddress.tryParse(good), isNotNull, reason: good);
      }
      expect(isPrivateNetworkAddress('172.32.0.1'), isFalse);
      expect(isPrivateNetworkAddress('100.128.0.1'), isFalse);
      expect(isPrivateNetworkAddress('::ffff:8.8.8.8'), isFalse);
    });

    test('manual input fills in the default port', () {
      expect('${LocalAddress.parseInput('192.168.1.5')}', '192.168.1.5:47821');
      expect('${LocalAddress.parseInput('fd00::5')}', '[fd00::5]:47821');
      expect('${LocalAddress.parseInput('10.0.0.2:5000')}', '10.0.0.2:5000');
      expect(() => LocalAddress.parseInput('1.1.1.1'), throwsFormatException);
    });
  });

  group('against a fake Host', () {
    late _FakeLocalHost host;
    late MemorySecretStore secrets;
    late LocalDirectClient client;

    setUp(() async {
      host = await _FakeLocalHost.start();
      secrets = MemorySecretStore();
      client = LocalDirectClient(secrets: secrets, deviceName: 'Test Phone', clientVersion: '1.0.0');
    });

    tearDown(() async {
      await client.close();
      await host.stop();
    });

    test('pairs by QR code, remembers the Host and connects again', () async {
      final link = LocalPairingLink.parse(host.pairingLink());
      final paired = await client.pair(link);
      expect(paired.hostDeviceId, host.deviceId);
      expect(paired.hostIdentityKey, host.keys.publicKeyBase64Url);
      expect(paired.name, 'Fake Host');
      expect(paired.pairingId, host.pairingId);
      expect(host.paired.single.$2, 'Test Phone');
      expect((await client.hosts()).single.addresses.single, host.address);
      expect(host.pairingCode, isNull, reason: 'single use');

      final dsh = await client.connectHost(paired.hostDeviceId, timeout: const Duration(seconds: 10));
      addTearDown(dsh.close);
      expect(host.methods.first, 'harness.transport.describe');
      expect(host.intents, ['pair', 'connect']);
      expect(dsh.remoteCarrier?.session?.transport, 'local');
    });

    test('a wrong pairing code is refused and nothing is stored', () async {
      final link = LocalPairingLink.parse(host.pairingLink(code: 'AAAAAAAAAAAAAAAAAAAAAA'));
      await expectLater(
        client.pair(link),
        throwsA(isA<RemoteConnectException>().having((e) => e.code, 'code', 'PAIRING_REJECTED')),
      );
      expect(await client.hosts(), isEmpty);
    });

    test('a Host whose key differs from the QR code is refused before the handshake', () async {
      final other = X25519KeyPair.generate().publicKeyBase64Url;
      final link = LocalPairingLink.parse(host.pairingLink(key: other));
      await expectLater(
        client.pair(link),
        throwsA(isA<RemoteConnectException>().having((e) => e.code, 'code', 'HOST_UNREACHABLE')),
      );
      expect(host.handshakes, 0);
      expect(await client.hosts(), isEmpty);
    });

    test('remembered addresses are tried in order and the working one moves first', () async {
      final paired = await client.pair(LocalPairingLink.parse(host.pairingLink()));
      // A closed port first: refused quickly, then the Host's address.
      final dead = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final deadAddress = LocalAddress.parse('127.0.0.1:${dead.port}');
      await dead.close();
      await client.setAddresses(paired.hostDeviceId, [deadAddress, host.address]);
      final dsh = await client.connectHost(paired.hostDeviceId, timeout: const Duration(seconds: 15));
      addTearDown(dsh.close);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect((await client.host(paired.hostDeviceId))!.addresses, [host.address, deadAddress]);
    });

    test('a Host that answers on no address fails fast instead of waiting out the timeout', () async {
      final paired = await client.pair(LocalPairingLink.parse(host.pairingLink()));
      await host.stop();
      final watch = Stopwatch()..start();
      await expectLater(
        client.connectHost(paired.hostDeviceId, timeout: const Duration(seconds: 30)),
        throwsA(isA<RemoteConnectException>().having((e) => e.code, 'code', 'HOST_UNREACHABLE')),
      );
      expect(watch.elapsed, lessThan(const Duration(seconds: 10)));
    });

    test('an unpaired device is refused with PEER_NOT_PAIRED', () async {
      final paired = await client.pair(LocalPairingLink.parse(host.pairingLink()));
      host.paired.clear();
      await expectLater(
        client.connectHost(paired.hostDeviceId, timeout: const Duration(seconds: 10)),
        throwsA(isA<RemoteConnectException>().having((e) => e.code, 'code', 'PEER_NOT_PAIRED')),
      );
    });
  });
}

/// Minimal Local Direct Host (upstream packages/plugin/src/local-host.ts):
/// hello / ack / Noise IK / pairing proof, then just enough Remote RPC for a
/// [DshClient] to become ready.
class _FakeLocalHost {
  _FakeLocalHost._(this._server, this.keys);

  static Future<_FakeLocalHost> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final host = _FakeLocalHost._(server, X25519KeyPair.generate());
    server.listen(host._onRequest);
    return host;
  }

  final HttpServer _server;
  final X25519KeyPair keys;
  final String deviceId = uuidV7();
  final String pairingId = uuidV7();
  String? pairingCode = 'wMHCw8TFxsfIycrLzM3Ozw';

  /// (deviceId, name, publicKey)
  final List<(String, String, String)> paired = [];
  final List<String> intents = [];
  final List<String> methods = [];
  int handshakes = 0;

  LocalAddress get address => LocalAddress.parse('127.0.0.1:${_server.port}');

  String pairingLink({String? code, String? key}) =>
      'dshremote://local-pair?v=1&id=$deviceId&k=${key ?? keys.publicKeyBase64Url}&a=$address'
      '&c=${code ?? pairingCode}&n=Fake+Host';

  Future<void> stop() => _server.close(force: true);

  Future<void> _onRequest(HttpRequest request) async {
    if (request.uri.path != localDirectPath) {
      request.response.statusCode = 404;
      await request.response.close();
      return;
    }
    final ws = await WebSocketTransformer.upgrade(request);
    try {
      await _serve(ws);
    } on StateError {
      // The client went away (e.g. it refused this Host's key).
    }
  }

  Future<void> _serve(WebSocket ws) async {
    final frames = StreamIterator<Object?>(ws);
    void error(String code) {
      ws.add(
        jsonEncode({
          'v': 1,
          'type': 'local.error',
          'payload': {'code': code, 'message': code},
        }),
      );
      unawaited(ws.close(1008));
    }

    Future<Map<String, Object?>> nextText() async {
      if (!await frames.moveNext()) throw StateError('closed');
      return _m(jsonDecode(frames.current! as String));
    }

    final hello = _m((await nextText())['payload']);
    final clientId = hello['clientDeviceId']! as String;
    final clientKey = hello['clientIdentityKey']! as String;
    intents.add(hello['intent']! as String);
    if (hello['intent'] == 'connect' && !paired.any((p) => p.$1 == clientId && p.$3 == clientKey)) {
      return error('PEER_NOT_PAIRED');
    }
    final connectionId = uuidV7();
    ws.add(
      jsonEncode({
        'v': 1,
        'type': 'local.hello.ack',
        'payload': {
          'hostDeviceId': deviceId,
          'hostIdentityKey': keys.publicKeyBase64Url,
          'name': 'Fake Host',
          'connectionId': connectionId,
          'capabilities': <String>[],
        },
      }),
    );
    final noise = NoiseIkSession(
      role: NoiseRole.responder,
      localPrivateKey: keys.privateKeyBase64Url,
      localPublicKey: keys.publicKeyBase64Url,
      remotePublicKey: clientKey,
      prologue: createLocalNoisePrologue(connectionId, deviceId, clientId),
    );
    final step1 = _m((await nextText())['payload']);
    noise.readHandshake(fromBase64Url(step1['data']! as String));
    final reply = noise.writeHandshake();
    handshakes++;
    ws.add(
      jsonEncode({
        'v': 1,
        'type': 'secure.handshake',
        'payload': {'connectionId': connectionId, 'step': 2, 'data': toBase64Url(reply)},
      }),
    );
    if (hello['intent'] == 'pair') {
      if (!await frames.moveNext()) return;
      final prove = _m(jsonDecode(utf8.decode(noise.decrypt(frames.current! as List<int>))));
      final code = pairingCode;
      final proof = _m(prove['payload'])['proof'];
      if (code == null || proof != createLocalPairingProof(code, noise.handshakeHash)) {
        return error('PAIRING_REJECTED');
      }
      pairingCode = null;
      paired.add((clientId, hello['name']! as String, clientKey));
      ws.add(
        noise.encrypt(
          utf8.encode(
            jsonEncode({
              'v': 1,
              'type': 'local.pair.ok',
              'payload': {'pairingId': pairingId},
            }),
          ),
        ),
      );
    }
    final incoming = SecureMessageCodec();
    final outgoing = SecureMessageCodec();
    void send(RemoteMessage message) {
      for (final fragment in outgoing.encode(message.encode())) {
        ws.add(noise.encrypt(fragment));
      }
    }

    while (await frames.moveNext()) {
      final plaintext = incoming.decode(noise.decrypt(frames.current! as List<int>));
      if (plaintext == null) continue;
      final message = RemoteMessage.decode(plaintext);
      if (message.type != 'rpc.request') continue;
      final payload = _m(message.payload);
      final method = payload['method']! as String;
      final params = _m(payload['params'] ?? <String, Object?>{});
      methods.add(method);
      void respond(Object? result) => send(RemoteMessage('rpc.response', {'requestId': message.id, 'result': result}));
      switch (method) {
        case 'harness.transport.describe':
          respond({
            'capabilities': ['harness.remote.v3'],
          });
        case 'harness.remote.stream.open':
          final streamId = params['streamId']! as String;
          respond({'opened': true, 'streamId': streamId});
          if (params['endpoint'] == r'$events') {
            send(
              RemoteMessage('event', {
                'event': 'harness.remote.frame',
                'data': {
                  'streamId': streamId,
                  'hasValue': true,
                  'value': {
                    'type': 'ready',
                    'clientId': 'local-client',
                    'host': {'home': '/home/host'},
                  },
                },
              }),
            );
          }
        case 'harness.remote.stream.close':
          respond({'closed': true, 'streamId': params['streamId']});
        default:
          send(
            RemoteMessage('rpc.error', {
              'requestId': message.id,
              'code': 'METHOD_NOT_FOUND',
              'message': 'Unknown method $method.',
              'retryable': false,
            }),
          );
      }
    }
  }
}
