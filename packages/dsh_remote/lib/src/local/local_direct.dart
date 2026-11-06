// Portions derived from ds-harness-remote (https://github.com/liguobao/ds-harness-remote), MIT, Copyright (c) 2026 DSH Remote contributors. See THIRD_PARTY_NOTICES.md.
// Local Direct client: pair with a Host by its QR code and connect to it
// straight over a private network (LAN, WireGuard, Tailscale), without any
// Remote Server or account.
library;

import 'dart:async';
import 'dart:convert';

import 'package:dsh_client/dsh_client.dart';

import '../account/host_negotiation.dart';
import '../account/secret_store.dart';
import '../carrier/tunnel_carrier.dart';
import '../channel/rpc_client.dart';
import '../channel/secure_channel.dart';
import '../crypto/noise_ik.dart';
import '../protocol/control.dart' show ProtocolError;
import '../state.dart';
import '../transport/local_transport.dart';
import '../transport/transport.dart';
import '../util/bytes.dart';
import 'local_protocol.dart';

/// A Host this device has paired with: its pinned identity and the
/// addresses it was reached on, most recently successful first.
class LocalPairedHost {
  LocalPairedHost({
    required this.hostDeviceId,
    required this.hostIdentityKey,
    required this.name,
    required List<LocalAddress> addresses,
    required this.pairedAt,
    this.pairingId,
  }) : addresses = List.unmodifiable(addresses);

  static LocalPairedHost? fromJson(Object? value) {
    final json = asMap(value);
    if (json == null) return null;
    final id = json['hostDeviceId'];
    final key = json['hostIdentityKey'];
    final name = json['name'];
    final rawAddresses = json['addresses'];
    final pairedAt = DateTime.tryParse(asString(json['pairedAt']) ?? '');
    final pairingId = json['pairingId'];
    if (!isLocalDeviceId(id) || key is! String || !identityKeyPattern.hasMatch(key) || !isLocalDisplayName(name)) {
      return null;
    }
    if (rawAddresses is! List || pairedAt == null) return null;
    final addresses = [
      for (final raw in rawAddresses)
        if (raw is String) ?LocalAddress.tryParse(raw),
    ];
    return LocalPairedHost(
      hostDeviceId: id! as String,
      hostIdentityKey: key,
      name: name! as String,
      addresses: addresses,
      pairedAt: pairedAt,
      pairingId: isLocalDeviceId(pairingId) ? pairingId! as String : null,
    );
  }

  final String hostDeviceId;
  final String hostIdentityKey;

  /// Name the Host reported when pairing (untrusted display text).
  final String name;
  final List<LocalAddress> addresses;
  final DateTime pairedAt;
  final String? pairingId;

  /// `ABCD EF01 2345` of the pinned identity key.
  String get fingerprint => formatFingerprint(identityFingerprint(hostIdentityKey));

  LocalPairedHost copyWith({String? name, List<LocalAddress>? addresses}) => LocalPairedHost(
    hostDeviceId: hostDeviceId,
    hostIdentityKey: hostIdentityKey,
    name: name ?? this.name,
    addresses: addresses ?? this.addresses,
    pairedAt: pairedAt,
    pairingId: pairingId,
  );

  JsonMap toJson() => {
    'hostDeviceId': hostDeviceId,
    'hostIdentityKey': hostIdentityKey,
    'name': name,
    'addresses': [for (final a in addresses) '$a'],
    'pairedAt': pairedAt.toUtc().toIso8601String(),
    'pairingId': ?pairingId,
  };
}

/// Pairs with and connects to Local Direct Hosts.
///
/// The Client identity (device id + X25519 key) is separate from any
/// [RemoteAccount] identity: a Host refuses a device id that its account
/// trust store already knows. Identity and paired Hosts live in [secrets].
///
/// Addresses are tried in order, [addressTimeout] each for the socket and
/// `local.hello.ack`; the first one that works moves to the front.
class LocalDirectClient {
  LocalDirectClient({
    required SecretStore secrets,
    this.deviceName = 'DSH App',
    this.platform = 'dsh-app-android',
    this.clientVersion,
    this.connector,
    this.addressTimeout = const Duration(seconds: 3),
    this.handshakeTimeout = const Duration(seconds: 7),
    this.compactHistory = false,
  }) : _secrets = secrets;

  static const String _identityKey = 'dsh_remote.v1.local.identity';
  static const String _hostsKey = 'dsh_remote.v1.local.hosts';

  final SecretStore _secrets;
  final String deviceName;
  final String platform;
  final String? clientVersion;
  final LocalSocketConnector? connector;
  final Duration addressTimeout;

  /// Noise handshake (and pairing proof) deadline after `local.hello.ack`;
  /// the Host allows 10 s from the socket opening for all of it.
  final Duration handshakeTimeout;

  /// As [RemoteAccount.compactHistory]: captured by each [connectHost].
  bool compactHistory;

  _LocalIdentity? _identity;
  Future<_LocalIdentity>? _loadingIdentity;
  Future<void> _hostWrites = Future.value();
  final Map<String, ActiveRemoteConnection> _active = {};

  /// Paired Hosts, in pairing order.
  Future<List<LocalPairedHost>> hosts() async {
    final raw = await _secrets.read(_hostsKey);
    if (raw == null) return const [];
    final list = tryDecodeJson(raw);
    if (list is! List) return const [];
    return [for (final item in list) ?LocalPairedHost.fromJson(item)];
  }

  Future<LocalPairedHost?> host(String hostDeviceId) async {
    for (final h in await hosts()) {
      if (h.hostDeviceId == hostDeviceId) return h;
    }
    return null;
  }

  /// Pairs with the Host of a scanned [link]: connects to its addresses in
  /// order with `intent: pair`, requires the key from the link, proves the
  /// pairing code and waits for `local.pair.ok`. The pairing connection is
  /// closed afterwards; [connectHost] opens a normal one.
  ///
  /// Throws [RemoteConnectException] (`PAIRING_CLOSED`, `PAIRING_REJECTED`,
  /// `PEER_IDENTITY_MISMATCH`, `CONNECTION_FAILED`, ...).
  Future<LocalPairedHost> pair(LocalPairingLink link) async {
    try {
      return await _pair(link);
    } on ProtocolError catch (error) {
      throw RemoteConnectException(RemoteFailure(error.code, error.message, retryable: false));
    } on Object catch (error) {
      // A rejected proof arrives as local.error, closing the channel before
      // or instead of local.pair.ok.
      throw asRemoteConnectException(error);
    }
  }

  Future<LocalPairedHost> _pair(LocalPairingLink link) async {
    final identity = await _ensureIdentity();
    final (channel, address, ack) = await _openChannel(
      identity,
      hostDeviceId: link.hostDeviceId,
      hostIdentityKey: link.hostIdentityKey,
      addresses: link.addresses,
      intent: LocalIntent.pair,
    );
    try {
      final proof = createLocalPairingProof(link.pairingCode, channel.handshakeHash);
      await channel.send(encodeLocalPairProve(proof));
      final pairingId = decodeLocalPairOk(await channel.takeMessage(timeout: handshakeTimeout));
      final paired = LocalPairedHost(
        hostDeviceId: link.hostDeviceId,
        hostIdentityKey: link.hostIdentityKey,
        name: ack.name,
        addresses: _ordered(address, link.addresses),
        pairedAt: DateTime.now(),
        pairingId: pairingId,
      );
      await _updateHosts((list) => [...list.where((h) => h.hostDeviceId != paired.hostDeviceId), paired]);
      return paired;
    } finally {
      await channel.close();
    }
  }

  /// Replaces the remembered addresses of a paired Host (manual entry).
  Future<LocalPairedHost> setAddresses(String hostDeviceId, List<LocalAddress> addresses) async {
    if (addresses.isEmpty || addresses.length > localMaxAddresses) {
      throw ArgumentError.value(addresses.length, 'addresses', 'must be 1 to $localMaxAddresses addresses');
    }
    LocalPairedHost? updated;
    await _updateHosts(
      (list) => [
        for (final h in list)
          if (h.hostDeviceId == hostDeviceId) updated = h.copyWith(addresses: addresses.toSet().toList()) else h,
      ],
    );
    final result = updated;
    if (result == null) {
      throw const RemoteConnectException(
        RemoteFailure('PEER_NOT_PAIRED', 'This Host is not paired.', retryable: false),
      );
    }
    return result;
  }

  /// Forgets a paired Host and closes its connection. The Host keeps this
  /// device in its own list until it is revoked there.
  Future<void> forget(String hostDeviceId) async {
    await _active.remove(hostDeviceId)?.close();
    await _updateHosts((list) => [...list.where((h) => h.hostDeviceId != hostDeviceId)]);
  }

  /// Connects to a paired Host; same contract as [RemoteAccount.connectHost]
  /// (reconnects by itself, [onState] reports progress, throws
  /// [RemoteConnectException] when not ready within [timeout] or at once on
  /// terminal failures).
  Future<DshClient> connectHost(
    String hostDeviceId, {
    void Function(RemoteConnectionState state)? onState,
    MuxOptions muxOptions = const MuxOptions(),
    Duration timeout = const Duration(seconds: 30),
    Duration healthInterval = const Duration(seconds: 25),
    Duration healthTimeout = const Duration(seconds: 10),
    DshTracer? tracer,
  }) async {
    final historyMode = RemoteHistoryMode(compactHistory);
    await _active.remove(hostDeviceId)?.close();
    final carrier = RemoteTunnelCarrier(
      hostId: hostDeviceId,
      open: (_) => _openSession(hostDeviceId, historyMode),
      healthInterval: healthInterval,
      healthTimeout: healthTimeout,
      tracer: tracer,
    );
    final client = DshClient.withCarrier(carrier, muxOptions: muxOptions);
    final active = ActiveRemoteConnection(client, carrier);
    _active[hostDeviceId] = active;
    active.stateSub = carrier.states.listen((state) {
      onState?.call(state);
      if (state.phase == RemoteConnectionPhase.closed && identical(_active[hostDeviceId], active)) {
        _active.remove(hostDeviceId);
      }
    });
    carrier.attachMux(client.mux);

    final ready = client.mux.ready(timeout: timeout);
    final failFast = Completer<RemoteFailure>();
    final failSub = carrier.failures.listen((failure) {
      // No address answered: hand back to the caller's own backoff (like the
      // account path's HOST_OFFLINE) instead of waiting out [timeout].
      if (!failFast.isCompleted && (!failure.retryable || failure.code == 'HOST_UNREACHABLE')) {
        failFast.complete(failure);
      }
    });
    try {
      final outcome = await Future.any<Object?>([ready, failFast.future]);
      if (outcome is RemoteFailure) throw RemoteConnectException(outcome);
      return client;
    } on Object catch (error) {
      ready.ignore();
      if (identical(_active[hostDeviceId], active)) _active.remove(hostDeviceId);
      await active.close();
      if (error is RemoteConnectException) rethrow;
      throw RemoteConnectException(
        carrier.lastFailure ??
            switch (error) {
              DshCarrierRefusedException(:final code, :final message) => RemoteFailure(code, message, retryable: false),
              _ => RemoteFailure('CONNECTION_FAILED', '$error', retryable: true),
            },
      );
    } finally {
      await failSub.cancel();
    }
  }

  Future<void> close() async {
    final active = [..._active.values];
    _active.clear();
    for (final connection in active) {
      await connection.close();
    }
  }

  // ---------------------------------------------------------------------------

  Future<RemoteHostSession> _openSession(String hostDeviceId, RemoteHistoryMode historyMode) async {
    try {
      final identity = await _ensureIdentity();
      final host = await this.host(hostDeviceId);
      if (host == null) {
        throw const RemoteConnectException(
          RemoteFailure('PEER_NOT_PAIRED', 'This Host is not paired.', retryable: false),
        );
      }
      if (host.addresses.isEmpty) {
        throw const RemoteConnectException(
          RemoteFailure('CONNECTION_FAILED', 'No address is known for this Host.', retryable: false),
        );
      }
      final setup = Stopwatch()..start();
      final (channel, address, _) = await _openChannel(
        identity,
        hostDeviceId: host.hostDeviceId,
        hostIdentityKey: host.hostIdentityKey,
        addresses: host.addresses,
        intent: LocalIntent.connect,
      );
      if (address != host.addresses.first) {
        unawaited(
          _updateHosts(
            (list) => [
              for (final h in list)
                if (h.hostDeviceId == hostDeviceId) h.copyWith(addresses: _ordered(address, h.addresses)) else h,
            ],
          ).catchError((Object _) {}),
        );
      }
      final rpc = RemoteRpcClient(channel);
      return await negotiateRemoteHostSession(rpc, historyMode, (capabilities, workspaceTypes) {
        setup.stop();
        RemoteNetworkDiagnostics snapshot() => RemoteNetworkDiagnostics(
          transportMode: RemoteTransportMode.lan,
          connectionDuration: setup.elapsed,
          observedAt: DateTime.now(),
        );
        return RemoteHostSession(
          rpc: rpc,
          capabilities: capabilities,
          workspaceTypes: workspaceTypes,
          transport: 'local',
          networkDiagnostics: snapshot(),
          inspectNetwork: () async => snapshot(),
        );
      });
    } on Object catch (error) {
      throw asRemoteConnectException(error);
    }
  }

  /// Tries [addresses] in order: hello within [addressTimeout], then Noise IK
  /// against [hostIdentityKey]. A socket failure, timeout or another device
  /// answering moves on to the next address; a refusal from the Host itself
  /// stops (every address leads to the same Host).
  Future<(SecureChannel, LocalAddress, LocalHelloAck)> _openChannel(
    _LocalIdentity identity, {
    required String hostDeviceId,
    required String hostIdentityKey,
    required List<LocalAddress> addresses,
    required LocalIntent intent,
  }) async {
    final hello = LocalHello(
      clientDeviceId: identity.deviceId,
      clientIdentityKey: identity.publicKey,
      name: deviceName,
      platform: platform,
      clientVersion: clientVersion,
      intent: intent,
    );
    RemoteTransportException? best;
    for (final address in addresses) {
      final LocalTransport transport;
      try {
        transport = await LocalTransport.connect(
          address: address,
          hello: hello,
          expectedHostDeviceId: hostDeviceId,
          expectedHostIdentityKey: hostIdentityKey,
          timeout: addressTimeout,
          connector: connector,
        );
      } on RemoteTransportException catch (error) {
        final nextAddress = error.code == 'CONNECTION_FAILED' || error.code == 'PEER_IDENTITY_MISMATCH';
        if (!nextAddress) throw asRemoteConnectException(error);
        // A different device on a remembered address says more than a timeout.
        if (best == null || best.code == 'CONNECTION_FAILED') best = error;
        continue;
      }
      final channel = await SecureChannel.establish(
        transport: transport,
        clientDeviceId: identity.deviceId,
        clientPrivateKey: identity.privateKey,
        clientPublicKey: identity.publicKey,
        hostDeviceId: hostDeviceId,
        hostIdentityKey: hostIdentityKey,
        timeout: handshakeTimeout,
        prologue: createLocalNoisePrologue(transport.ack.connectionId, hostDeviceId, identity.deviceId),
      );
      return (channel, address, transport.ack);
    }
    final failure = best;
    if (failure == null) {
      throw const RemoteConnectException(
        RemoteFailure('CONNECTION_FAILED', 'No address is known for this Host.', retryable: false),
      );
    }
    throw RemoteConnectException(
      RemoteFailure(
        'HOST_UNREACHABLE',
        failure.message,
        // Another device on the address: the Host may come back on it later.
        retryable: true,
      ),
    );
  }

  static List<LocalAddress> _ordered(LocalAddress first, List<LocalAddress> rest) =>
      [first, ...rest.where((a) => a != first)].take(localMaxAddresses).toList();

  Future<void> _updateHosts(List<LocalPairedHost> Function(List<LocalPairedHost> hosts) change) {
    final write = _hostWrites.then((_) async {
      final next = change(await hosts());
      await _secrets.write(_hostsKey, jsonEncode([for (final h in next) h.toJson()]));
    });
    _hostWrites = write.catchError((Object _) {});
    return write;
  }

  Future<_LocalIdentity> _ensureIdentity() {
    final existing = _identity;
    if (existing != null) return Future.value(existing);
    return _loadingIdentity ??= _loadIdentity().whenComplete(() => _loadingIdentity = null);
  }

  Future<_LocalIdentity> _loadIdentity() async {
    final stored = _LocalIdentity.fromJson(tryDecodeJson(await _secrets.read(_identityKey) ?? ''));
    if (stored != null) return _identity = stored;
    final keys = X25519KeyPair.generate();
    final created = _LocalIdentity(uuidV7(), keys.privateKeyBase64Url, keys.publicKeyBase64Url);
    await _secrets.write(_identityKey, jsonEncode(created.toJson()));
    return _identity = created;
  }
}

class _LocalIdentity {
  const _LocalIdentity(this.deviceId, this.privateKey, this.publicKey);

  static _LocalIdentity? fromJson(Object? value) {
    final json = asMap(value);
    final id = json?['deviceId'];
    final privateKey = json?['privateKey'];
    final publicKey = json?['publicKey'];
    if (!isLocalDeviceId(id) || privateKey is! String || publicKey is! String) return null;
    if (!identityKeyPattern.hasMatch(publicKey)) return null;
    return _LocalIdentity(id! as String, privateKey, publicKey);
  }

  final String deviceId;
  final String privateKey;
  final String publicKey;

  JsonMap toJson() => {'v': 1, 'deviceId': deviceId, 'privateKey': privateKey, 'publicKey': publicKey};
}
