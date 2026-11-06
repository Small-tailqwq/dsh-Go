// Portions derived from ds-harness-remote (https://github.com/liguobao/ds-harness-remote), MIT, Copyright (c) 2026 DSH Remote contributors. See THIRD_PARTY_NOTICES.md.
// What every Host connection does once its secure channel is up, whichever
// way it was reached (account Relay / WebRTC, or Local Direct).
library;

import 'dart:async';

import 'package:dsh_client/dsh_client.dart';

import '../carrier/tunnel_carrier.dart';
import '../channel/rpc_client.dart';
import '../channel/secure_channel.dart';
import '../crypto/noise_ik.dart';
import '../protocol/control.dart' show maxRemoteCapabilityEntries;
import '../server/server_api.dart';
import '../state.dart';
import '../transport/transport.dart';
import '../util/bytes.dart';

/// Probes `harness.transport.describe` (always the first RPC), checks the
/// Harness Session format and configures compact history; then [build]
/// makes the session from the capabilities and `workspaceTypes`. Closes
/// [rpc] and throws [RemoteConnectException] on failure.
Future<RemoteHostSession> negotiateRemoteHostSession(
  RemoteRpcClient rpc,
  RemoteHistoryMode historyMode,
  RemoteHostSession Function(List<String> capabilities, Object? workspaceTypes) build,
) async {
  var probingCapabilities = true;
  try {
    final description = asMap(
      await rpc.call('harness.transport.describe', const <String, Object?>{}, timeout: const Duration(seconds: 10)),
    );
    probingCapabilities = false;
    final raw = description?['capabilities'];
    if (raw is! List ||
        raw.length > maxRemoteCapabilityEntries ||
        raw.any((c) => c is! String || c.isEmpty) ||
        raw.toSet().length != raw.length) {
      throw const RemoteConnectException(
        RemoteFailure('INVALID_MESSAGE', 'The Host returned invalid transport capabilities.', retryable: false),
      );
    }
    final capabilities = raw.cast<String>();
    final v3 = capabilities.contains('harness.remote.v3');
    final v1 = capabilities.contains('harness.remote.v1');
    if (v3 && v1) {
      throw const RemoteConnectException(
        RemoteFailure('INVALID_MESSAGE', 'The Host advertised conflicting Harness Session formats.', retryable: false),
      );
    }
    if (!v3) {
      throw RemoteConnectException(
        RemoteFailure(
          'HARNESS_VERSION_INCOMPATIBLE',
          v1
              ? 'The Host runs a pre-0.1.5 DSH (Session format v1); this client needs DSH 0.2.x (Session V3).'
              : 'The Host exposes no Typert Remote carrier (harness.remote.v3); update its ds-harness-remote plugin.',
          retryable: false,
        ),
      );
    }
    final supportsCompact = capabilities.contains('remote.history.compact.v1');
    final compact = historyMode.negotiated ?? (supportsCompact && historyMode.requested);
    if (compact && !supportsCompact) {
      throw const RemoteConnectException(
        RemoteFailure(
          'HISTORY_MODE_CHANGED',
          'The Host no longer supports compact history; create a new client to load full history.',
          retryable: false,
        ),
      );
    }
    if (supportsCompact) {
      final result = asMap(
        await rpc.call('remote.history.configure', {'compact': compact}, timeout: const Duration(seconds: 10)),
      );
      if (result == null || result.length != 1 || result['compact'] is! bool || result['compact'] != compact) {
        throw const RemoteConnectException(
          RemoteFailure('INVALID_MESSAGE', 'The Host returned an invalid history configuration.', retryable: false),
        );
      }
    }
    historyMode.negotiated = compact;
    return build(List.unmodifiable(capabilities), description!['workspaceTypes']);
  } on RemoteRpcException catch (error) {
    await rpc.close();
    if (probingCapabilities && error.code == 'METHOD_NOT_FOUND') {
      throw const RemoteConnectException(
        RemoteFailure(
          'HARNESS_VERSION_INCOMPATIBLE',
          'The Host plugin predates capability discovery (rc.2 ApiProxy only); update ds-harness-remote on the Host.',
          retryable: false,
        ),
      );
    }
    throw RemoteConnectException(RemoteFailure(error.code, error.message, retryable: error.retryable || error.isLocal));
  } on Object {
    await rpc.close();
    rethrow;
  }
}

RemoteConnectException asRemoteConnectException(Object error) => switch (error) {
  RemoteConnectException() => error,
  RemoteApiException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable || code == 'CONNECTION_FAILED' || code == 'HOST_OFFLINE'),
  ),
  RemoteTransportException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable && !_terminalCodes.contains(code)),
  ),
  SecureChannelException(:final code, :final message, :final retryable) => RemoteConnectException(
    RemoteFailure(code, message, retryable: retryable && !_terminalCodes.contains(code)),
  ),
  RemoteRpcException(:final code, :final message) => RemoteConnectException(
    RemoteFailure(code, message, retryable: true),
  ),
  NoiseSessionError(:final code, :final message) => RemoteConnectException(
    RemoteFailure(code, message, retryable: false),
  ),
  ArgumentError() => RemoteConnectException(RemoteFailure('INVALID_ARGUMENT', '$error', retryable: false)),
  _ => RemoteConnectException(RemoteFailure('CONNECTION_FAILED', '$error', retryable: true)),
};

const Set<String> _terminalCodes = {
  'CONNECTION_REPLACED',
  'CONNECTION_REJECTED',
  'PEER_IDENTITY_MISMATCH',
  'MEMBERSHIP_REQUIRED',
  'DEVICE_REVOKED',
  'DEVICE_NOT_FOUND',
  'CAPABILITY_NOT_SUPPORTED',
  'UNSUPPORTED_VERSION',
  'ACCOUNT_AUTH_REQUIRED',
};

// A client's transcript cache must not mix compact and full baselines.
/// Requested and (after the first session) negotiated compact history.
class RemoteHistoryMode {
  RemoteHistoryMode(this.requested);

  final bool requested;
  bool? negotiated;
}

/// [DshClient] plus carrier of one `connectHost`, closed together.
class ActiveRemoteConnection {
  ActiveRemoteConnection(this.client, this.carrier);

  final DshClient client;
  final RemoteTunnelCarrier carrier;
  StreamSubscription<RemoteConnectionState>? stateSub;
  bool _closed = false;

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await client.close();
    await Future<void>.delayed(Duration.zero);
    await stateSub?.cancel();
  }
}
