import 'dart:async';

import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_remote/dsh_remote.dart' as remote;

import '../../l10n/l10n.dart';
import '../link_status.dart';
import '../relay/dsh_remote_backend.dart';
import '../relay/relay_backend.dart';
import '../secret_store.dart';

/// 局域网主机: ds-harness-remote's Local Direct over `packages/dsh_remote`.
/// A Host paired by its QR code is reached straight over a private network
/// (same Wi-Fi, WireGuard, Tailscale): no Server, no account. Pairing pins the
/// Host's key; every later connect requires exactly that key.
///
/// Implements [RelayBackend] so [RelayHostLink] drives reconnects, progress
/// and the network status the same way as for DSH Remote; the account parts
/// are inert.
class LanBackend implements RelayBackend, RelayNetworkBackend {
  LanBackend({required SecretStore secrets, String clientVersion = '0.1.0', remote.LocalDirectClient? client})
    : client =
          client ??
          remote.LocalDirectClient(
            secrets: DshRemoteSecrets(secrets),
            deviceName: 'DSH App (Android)',
            platform: 'dsh-app-android',
            clientVersion: clientVersion,
          );

  final remote.LocalDirectClient client;

  /// As for DSH Remote: a sleeping computer isn't polled every few seconds.
  static const _muxOptions = MuxOptions(
    retryCaps: [
      Duration(milliseconds: 500),
      Duration(seconds: 1),
      Duration(seconds: 2),
      Duration(seconds: 4),
      Duration(seconds: 8),
      Duration(seconds: 15),
      Duration(seconds: 30),
      Duration(seconds: 60),
    ],
  );

  /// Applies to the next client.
  set compactHistory(bool enabled) => client.compactHistory = enabled;

  Future<List<remote.LocalPairedHost>> pairedHosts() => client.hosts();

  /// Pairs with the Host of a scanned or pasted `dshremote://local-pair` link.
  Future<remote.LocalPairedHost> pair(String link) async {
    final parsed = remote.LocalPairingLink.tryParse(link);
    if (parsed == null) throw HostLinkError(HostLinkErrorKind.other, appL10n.remoteLanErrInvalidLink);
    return _map(() => client.pair(parsed));
  }

  Future<remote.LocalPairedHost> setAddresses(String hostId, List<remote.LocalAddress> addresses) =>
      _map(() => client.setAddresses(hostId, addresses));

  Future<void> forget(String hostId) => client.forget(hostId);

  @override
  bool get available => true;

  @override
  String get serverLabel => '';

  @override
  Future<RelayUser?> currentUser() async => null;

  @override
  Future<List<RelayAuthProvider>> loginProviders() async => const [];

  @override
  Future<RelayLoginSession> login({String? providerId}) => Future.error(UnsupportedError('no account'));

  @override
  Future<RelayUser> loginWithPassword(String email, String password) => Future.error(UnsupportedError('no account'));

  @override
  Future<void> logout() async {}

  @override
  Future<List<RelayHost>> listHosts({bool refresh = false}) async => [for (final h in await client.hosts()) host(h)];

  /// Paired Hosts are always worth trying: presence is only known by connecting.
  static RelayHost host(remote.LocalPairedHost h) =>
      RelayHost(id: h.hostDeviceId, name: h.name, online: true, fingerprint: h.fingerprint);

  @override
  void approveHost(RelayHost host) {}

  @override
  Future<void> forgetHost(RelayHost host) async {}

  @override
  bool reconnect(DshClient client) {
    final carrier = client.remoteCarrier;
    if (carrier == null || carrier.isClosed) return false;
    carrier.reconnect();
    return true;
  }

  @override
  Future<bool> probe(DshClient client) => client.remoteCarrier?.probe() ?? Future.value(true);

  @override
  RelayPath? pathOf(DshClient client) {
    final session = client.remoteCarrier?.session;
    return session == null || session.isClosed ? null : RelayPath.localDirect;
  }

  @override
  RemoteNetworkStatus? networkOf(DshClient client) {
    final session = client.remoteCarrier?.session;
    final snapshot = session?.networkDiagnostics;
    if (session == null || session.isClosed || snapshot == null) return null;
    return RemoteNetworkStatus(
      path: RelayPath.localDirect,
      connectDuration: snapshot.connectionDuration,
      observedAt: snapshot.observedAt,
    );
  }

  @override
  Future<RemoteNetworkStatus?> inspectNetwork(DshClient client) async => networkOf(client);

  @override
  Future<DshClient> connectHost(RelayHost host, {RelayStateCallback? onState}) => _map(
    () => client.connectHost(
      host.id,
      muxOptions: _muxOptions,
      timeout: const Duration(seconds: 45),
      onState: onState == null
          ? null
          : (s) => onState(switch (s.phase) {
              remote.RemoteConnectionPhase.connecting => RelayConnectionState.connecting,
              remote.RemoteConnectionPhase.connected => RelayConnectionState.connected,
              remote.RemoteConnectionPhase.reconnecting => RelayConnectionState.reconnecting,
              remote.RemoteConnectionPhase.failed => RelayConnectionState.failed,
              remote.RemoteConnectionPhase.closed => RelayConnectionState.disconnected,
            }, s.failure == null ? null : describe(s.failure!, host.name)),
    ),
    hostName: host.name,
  );

  Future<void> close() => client.close();

  static Future<T> _map<T>(Future<T> Function() action, {String? hostName}) async {
    try {
      return await action();
    } on remote.RemoteConnectException catch (e) {
      throw describe(e.failure, hostName);
    }
  }

  /// UI text for Local Direct failures; the rest as for DSH Remote.
  static HostLinkError describe(remote.RemoteFailure failure, [String? hostName]) {
    final detail = '${failure.code}: ${failure.message}';
    HostLinkError e(HostLinkErrorKind kind, String message, {bool? retryable}) =>
        HostLinkError(kind, message, detail: detail, retryable: retryable ?? failure.retryable);
    return switch (failure.code) {
      'PAIRING_CLOSED' => e(HostLinkErrorKind.other, appL10n.remoteLanErrPairingClosed, retryable: false),
      'PAIRING_REJECTED' => e(HostLinkErrorKind.other, appL10n.remoteLanErrPairingRejected, retryable: false),
      'PEER_NOT_PAIRED' => e(HostLinkErrorKind.hostKeyRejected, appL10n.remoteLanErrNotPaired, retryable: false),
      'PEER_IDENTITY_MISMATCH' => e(HostLinkErrorKind.hostKeyMismatch, appL10n.remoteLanErrIdentityChanged),
      'CONNECTION_FAILED' ||
      'HOST_UNREACHABLE' => e(HostLinkErrorKind.unreachable, appL10n.remoteLanErrUnreachable, retryable: true),
      _ => DshRemoteRelayBackend.describe(failure, hostName),
    };
  }
}
