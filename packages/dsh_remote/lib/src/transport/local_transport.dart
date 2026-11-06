// Portions derived from ds-harness-remote (https://github.com/liguobao/ds-harness-remote), MIT, Copyright (c) 2026 DSH Remote contributors. See THIRD_PARTY_NOTICES.md.
// Local Direct data plane: one WebSocket straight to the Host on a private
// network (`ws://<addr>/dsh-remote/local/v1`). Text frames carry control JSON
// (`local.hello`, `local.hello.ack`, `secure.handshake`, `local.error`),
// binary frames carry Noise ciphertext. No Server is involved.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../local/local_protocol.dart';
import '../protocol/control.dart' show ProtocolError;
import 'transport.dart';

/// Opens the Local Direct WebSocket; injectable for tests.
typedef LocalSocketConnector = Future<WebSocket> Function(Uri url, Duration timeout);

Future<WebSocket> _defaultConnector(Uri url, Duration timeout) {
  var expired = false;
  final opening = WebSocket.connect(url.toString()).then((socket) {
    if (expired) unawaited(socket.close(WebSocketStatus.normalClosure).catchError((Object _) {}));
    return socket;
  });
  return opening.timeout(
    timeout,
    onTimeout: () {
      expired = true;
      throw TimeoutException('Local Direct connect timed out', timeout);
    },
  );
}

/// [SecureHandshakeTransport] over a Local Direct WebSocket.
///
/// [connect] sends `local.hello` and waits for `local.hello.ack`. The Host's
/// key in the ack must equal [expectedHostIdentityKey] (the pinned key, or the
/// one from the pairing QR code) and its device id [expectedHostDeviceId];
/// otherwise the socket is closed with `PEER_IDENTITY_MISMATCH` before any
/// handshake. Noise ciphertext carries no relay counter: the WebSocket is
/// ordered, and Noise itself rejects reordering.
class LocalTransport implements SecureHandshakeTransport {
  LocalTransport._(this._socket, this.address, this.ack, this._clientDeviceId);

  /// Opens [address], says hello and validates the Host's answer within
  /// [timeout]. Throws [RemoteTransportException].
  static Future<LocalTransport> connect({
    required LocalAddress address,
    required LocalHello hello,
    required String expectedHostDeviceId,
    required String expectedHostIdentityKey,
    Duration timeout = const Duration(seconds: 3),
    LocalSocketConnector? connector,
  }) async {
    final deadline = DateTime.now().add(timeout);
    final WebSocket socket;
    try {
      socket = await (connector ?? _defaultConnector)(address.webSocketUri, timeout);
    } on TimeoutException {
      throw const RemoteTransportException('CONNECTION_FAILED', 'The Host did not answer on this address in time.');
    } on WebSocketException catch (error) {
      throw RemoteTransportException('CONNECTION_FAILED', 'Local Direct WebSocket failed: ${error.message}');
    } on SocketException catch (error) {
      throw RemoteTransportException('CONNECTION_FAILED', 'Local Direct connect failed: ${error.message}');
    } on HttpException catch (error) {
      throw RemoteTransportException('CONNECTION_FAILED', 'Local Direct connect failed: ${error.message}');
    }
    final pending = _PendingAck(socket);
    try {
      socket.add(hello.encode());
      final remaining = deadline.difference(DateTime.now());
      final frame = await pending.first.timeout(remaining.isNegative ? Duration.zero : remaining);
      final ack = switch (frame) {
        LocalAckFrame(:final ack) => ack,
        LocalErrorFrame(:final code, :final message) => throw RemoteTransportException(
          code,
          message.isEmpty ? 'The Host refused the connection.' : message,
          retryable: _retryableHostCodes.contains(code),
        ),
        LocalHandshakeFrame() => throw const RemoteTransportException(
          'INVALID_MESSAGE',
          'The Host sent a handshake before local.hello.ack.',
          retryable: false,
        ),
      };
      if (ack.hostDeviceId != expectedHostDeviceId || ack.hostIdentityKey != expectedHostIdentityKey) {
        throw const RemoteTransportException(
          'PEER_IDENTITY_MISMATCH',
          'The Host at this address presented a different identity than the one paired with.',
          retryable: false,
        );
      }
      final transport = LocalTransport._(socket, address, ack, hello.clientDeviceId);
      pending.handOver(transport);
      return transport;
    } on Object catch (error) {
      pending.cancel();
      unawaited(socket.close(WebSocketStatus.normalClosure).catchError((Object _) {}));
      if (error is RemoteTransportException) rethrow;
      if (error is TimeoutException) {
        throw const RemoteTransportException('CONNECTION_FAILED', 'The Host did not answer local.hello in time.');
      }
      if (error is ProtocolError) {
        throw RemoteTransportException(error.code, error.message, retryable: false);
      }
      throw RemoteTransportException('CONNECTION_FAILED', 'Local Direct hello failed: $error');
    }
  }

  static const Set<String> _retryableHostCodes = {'RATE_LIMITED', 'HOST_STOPPING'};

  final WebSocket _socket;
  final LocalAddress address;
  final LocalHelloAck ack;
  final String _clientDeviceId;
  StreamSubscription<Object?>? _subscription;

  TransportDataHandler? _onData;
  TransportHandshakeHandler? _onHandshake;
  TransportClosedHandler? _onClosed;
  final List<void Function()> _backlog = [];
  RemoteTransportClosed? _pendingClose;
  bool _secure = false;
  bool _closed = false;

  /// The connection the Host just accepted, on a private network.
  @override
  RemoteTransportMode get mode => RemoteTransportMode.lan;

  @override
  RemoteConnectionInfo get info => RemoteConnectionInfo(
    connectionId: ack.connectionId,
    localDeviceId: _clientDeviceId,
    remoteDeviceId: ack.hostDeviceId,
  );

  void _attach(StreamSubscription<Object?> subscription) {
    _subscription = subscription;
    subscription.onData(_onFrame);
    subscription.onError(
      (Object error) => _fail(RemoteTransportClosed('CONNECTION_FAILED', 'Local socket error: $error')),
    );
    subscription.onDone(() => _fail(_closeReason()));
  }

  RemoteTransportClosed _closeReason() {
    final code = _socket.closeCode;
    final reason = _socket.closeReason ?? '';
    final known = RegExp(r'^[A-Z][A-Z0-9_]+$').hasMatch(reason) ? reason : null;
    return RemoteTransportClosed(
      known ?? 'CONNECTION_FAILED',
      'Local Direct connection closed (${code ?? 'no code'} $reason)'.trim(),
      retryable: known == null || _retryableHostCodes.contains(known) || known == 'SECURE_CHANNEL_FAILED',
      closeCode: code,
    );
  }

  void _onFrame(Object? data) {
    if (_closed) return;
    try {
      if (data is String) {
        final frame = decodeLocalControlFrame(data);
        switch (frame) {
          case LocalHandshakeFrame(:final connectionId, :final step, data: final bytes):
            if (_secure || connectionId != ack.connectionId) {
              throw const ProtocolError('Unexpected secure.handshake.');
            }
            if (step == 2) _secure = true;
            _deliver(() => _onHandshake!(step, bytes));
          case LocalErrorFrame(:final code, :final message):
            _fail(
              RemoteTransportClosed(
                code,
                message.isEmpty ? 'The Host closed the connection.' : message,
                retryable: _retryableHostCodes.contains(code) || code == 'SECURE_CHANNEL_FAILED',
              ),
            );
          case LocalAckFrame():
            throw const ProtocolError('Duplicate local.hello.ack.');
        }
      } else if (data is List<int>) {
        final bytes = data is Uint8List ? data : Uint8List.fromList(data);
        _deliver(() => _onData!(bytes, null));
      }
    } on ProtocolError catch (error) {
      _fail(RemoteTransportClosed(error.code, error.message, retryable: false));
    }
  }

  void _deliver(void Function() action) {
    if (_onData == null) {
      _backlog.add(action);
    } else {
      action();
    }
  }

  @override
  void listen({
    required TransportDataHandler onData,
    required TransportHandshakeHandler onHandshake,
    required TransportClosedHandler onClosed,
  }) {
    _onData = onData;
    _onHandshake = onHandshake;
    _onClosed = onClosed;
    final backlog = [..._backlog];
    _backlog.clear();
    for (final action in backlog) {
      action();
    }
    final pending = _pendingClose;
    if (pending != null) {
      _pendingClose = null;
      onClosed(pending);
    }
  }

  @override
  Future<void> sendHandshake(int step, Uint8List data) async {
    if (_closed) throw const RemoteTransportException('CONNECTION_FAILED', 'The Local Direct connection is closed.');
    _socket.add(encodeLocalHandshake(ack.connectionId, step, data));
  }

  @override
  Future<void> send(Uint8List ciphertext, {required int counter}) async {
    if (_closed) throw const RemoteTransportException('CONNECTION_FAILED', 'The Local Direct connection is closed.');
    _socket.add(ciphertext);
  }

  void _fail(RemoteTransportClosed reason) {
    if (_closed) return;
    _closed = true;
    unawaited(_subscription?.cancel());
    unawaited(_socket.close(WebSocketStatus.normalClosure).catchError((Object _) {}));
    final handler = _onClosed;
    if (handler == null) {
      _pendingClose = reason;
    } else {
      handler(reason);
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _onClosed = null;
    await _subscription?.cancel();
    await _socket.close(WebSocketStatus.normalClosure).catchError((Object _) {});
  }
}

/// Reads frames until `local.hello.ack`, then hands the subscription to the
/// transport so no later frame is lost.
class _PendingAck {
  _PendingAck(WebSocket socket) {
    _subscription = socket.listen(
      (data) {
        if (_completer.isCompleted) {
          _queued.add(data);
          return;
        }
        try {
          if (data is! String) throw const ProtocolError('Binary frame before local.hello.ack.');
          _completer.complete(decodeLocalControlFrame(data));
        } on Object catch (error) {
          _completer.completeError(error);
        }
      },
      onError: (Object error) {
        if (!_completer.isCompleted) {
          _completer.completeError(RemoteTransportException('CONNECTION_FAILED', 'Local socket error: $error'));
        }
      },
      onDone: () {
        _done = true;
        if (!_completer.isCompleted) {
          final reason = socket.closeReason ?? '';
          _completer.completeError(
            RemoteTransportException(
              'CONNECTION_FAILED',
              'The Host closed the connection before answering (${socket.closeCode ?? 'no code'} $reason)'.trim(),
            ),
          );
        }
      },
    );
  }

  late final StreamSubscription<Object?> _subscription;
  final Completer<LocalControlFrame> _completer = Completer();
  final List<Object?> _queued = [];
  bool _done = false;

  Future<LocalControlFrame> get first => _completer.future;

  void handOver(LocalTransport transport) {
    transport._attach(_subscription);
    for (final data in _queued) {
      transport._onFrame(data);
    }
    _queued.clear();
    if (_done) transport._fail(transport._closeReason());
  }

  void cancel() {
    unawaited(_subscription.cancel());
  }
}
