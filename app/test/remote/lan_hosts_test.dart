// 局域网主机 (ds-harness-remote Local Direct): the host reference, failure
// texts, and the pairing / address dialogs on the remote page.

import 'dart:async';
import 'dart:io';

import 'package:dsh_app/l10n/l10n.dart';
import 'package:dsh_app/remote/lan/lan_backend.dart';
import 'package:dsh_app/remote/secret_store.dart';
import 'package:dsh_app/runtime/runtime_state.dart';
import 'package:dsh_app/state/connection_state.dart';
import 'package:dsh_app/state/hosts_state.dart';
import 'package:dsh_app/ui/remote/lan_hosts.dart';
import 'package:dsh_app/ui/remote/remote_screen.dart';
import 'package:dsh_remote/dsh_remote.dart' as remote;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../shell/golden_harness.dart';
import 'support/fake_relay.dart';

const _hostId = '0198f3a2-6b1c-7d2e-8f30-4a5b6c7d8e9f';

Future<void> _seedPairedHost(MemorySecretStore secrets) => secrets.write(
  'dsh_remote.v1.local.hosts',
  '[{"hostDeviceId":"$_hostId","hostIdentityKey":"${remote.X25519KeyPair.generate().publicKeyBase64Url}",'
      '"name":"书房电脑","addresses":["192.168.1.10:47821"],"pairedAt":"2026-11-06T00:00:00.000Z"}]',
);

void main() {
  test('a LAN host reference survives the saved active host', () {
    const ref = HostRef.lan(_hostId, name: '书房电脑');
    final decoded = HostRef.decode(ref.encode());
    expect(decoded, ref);
    expect(decoded.kind, HostKind.lan);
    expect(decoded.name, '书房电脑');
    expect(HostKind.lan.viaRemoteTunnel, isTrue);
    expect(HostKind.ssh.viaRemoteTunnel, isFalse);
  });

  test('Local Direct failures get their own texts; pairing ones need the person', () {
    HostLinkError describe(String code, {bool retryable = false}) =>
        LanBackend.describe(remote.RemoteFailure(code, 'x', retryable: retryable));
    expect(describe('PAIRING_REJECTED').message, appL10n.remoteLanErrPairingRejected);
    expect(describe('PAIRING_CLOSED').retryable, isFalse);
    expect(describe('PEER_NOT_PAIRED').message, appL10n.remoteLanErrNotPaired);
    expect(describe('PEER_IDENTITY_MISMATCH').kind, HostLinkErrorKind.hostKeyMismatch);
    final unreachable = describe('CONNECTION_FAILED');
    expect(unreachable.kind, HostLinkErrorKind.unreachable);
    expect(unreachable.retryable, isTrue);
  });

  test('a malformed pairing link is refused before any connection', () async {
    final backend = LanBackend(secrets: MemorySecretStore());
    addTearDown(backend.close);
    await expectLater(
      backend.pair('dshremote://local-pair?v=1&id=x'),
      throwsA(isA<HostLinkError>().having((e) => e.message, 'message', appL10n.remoteLanErrInvalidLink)),
    );
    expect(await backend.pairedHosts(), isEmpty);
  });

  group('remote page', () {
    late MemorySecretStore secrets;

    setUp(() {
      secrets = MemorySecretStore();
      SharedPreferences.setMockInitialValues({});
    });

    Future<ProviderContainer> pump(WidgetTester tester) async {
      usePhoneSurface(tester);
      await tester.pumpWidget(
        goldenApp(
          home: const RemoteScreen(),
          brightness: Brightness.light,
          overrides: [
            secretStoreProvider.overrideWithValue(secrets),
            networkKicksProvider.overrideWithValue(const Stream.empty()),
            relayBackendProvider.overrideWithValue(FakeRelayBackend()),
            hostLinkStatusProvider.overrideWith((ref, host) => Stream.value(HostLinkStatus.idle)),
            localRuntimeProvider.overrideWith(
              () => FakeRuntime(const LocalRuntimeState(loaded: true, status: runningStatus)),
            ),
          ],
        ),
      );
      for (var i = 0; i < 6; i++) {
        await tester.pump(const Duration(milliseconds: 60));
      }
      return ProviderScope.containerOf(tester.element(find.byType(MaterialApp)));
    }

    testWidgets('lists paired LAN hosts and refuses a bad pairing link', (tester) async {
      await _seedPairedHost(secrets);
      await pump(tester);
      await tester.scrollUntilVisible(find.byKey(const ValueKey('lan-pair')), 200);
      expect(find.text('书房电脑'), findsOneWidget);
      expect(find.text('192.168.1.10:47821'), findsOneWidget);

      await tester.tap(find.byKey(const ValueKey('lan-pair')));
      await tester.pump(const Duration(milliseconds: 400));
      await tester.enterText(find.byKey(const ValueKey('lan-pair-link')), 'https://example.com');
      await tester.tap(find.text(appL10n.remoteLanPair));
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text(appL10n.remoteLanErrInvalidLink), findsOneWidget);
    });

    testWidgets('a scanned link shows the Host name and fingerprint and waits for the tap', (tester) async {
      var connects = 0;
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      server.listen((socket) {
        connects++;
        socket.destroy();
      });
      final key = remote.X25519KeyPair.generate().publicKeyBase64Url;
      final link =
          'dshremote://local-pair?v=1&id=$_hostId&k=$key&a=127.0.0.1%3A${server.port}'
          '&c=wMHCw8TFxsfIycrLzM3Ozw&n=%E4%B9%A6%E6%88%BF%E7%94%B5%E8%84%91';
      final container = await pump(tester);
      unawaited(showLanPairing(tester.element(find.byType(RemoteScreen)), initialLink: link));
      await tester.pump(const Duration(milliseconds: 400));

      final fingerprint = remote.formatFingerprint(remote.identityFingerprint(key));
      expect(find.byKey(const ValueKey('lan-pair-preview')), findsOneWidget);
      expect(find.text('书房电脑'), findsOneWidget);
      expect(find.text(appL10n.remoteLanFingerprint(fingerprint)), findsOneWidget);
      expect(find.text('127.0.0.1:${server.port}'), findsOneWidget);
      await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 200)));
      expect(connects, 0, reason: 'nothing connects before 配对');
      expect(container.read(lanHostsProvider).value, isEmpty);

      // Same Host key, other name and address: the preview follows every edit.
      await tester.enterText(
        find.byKey(const ValueKey('lan-pair-link')),
        link.replaceFirst('127.0.0.1', '192.168.1.20').replaceFirst(RegExp(r'&n=.*$'), '&n=Den'),
      );
      await tester.pump();
      expect(find.text('Den'), findsOneWidget);
      expect(find.text('书房电脑'), findsNothing);
      expect(find.text('192.168.1.20:${server.port}'), findsOneWidget);

      await tester.tap(find.text(appL10n.commonCancel));
      await tester.pump(const Duration(milliseconds: 400));
      expect(find.byKey(const ValueKey('lan-pair-preview')), findsNothing);
    });

    testWidgets('editing addresses accepts private IPs only, with the default port', (tester) async {
      await _seedPairedHost(secrets);
      final container = await pump(tester);
      await tester.scrollUntilVisible(find.byKey(const ValueKey('lan-pair')), 200);
      await tester.tap(find.byTooltip(appL10n.commonEdit).last);
      await tester.pump(const Duration(milliseconds: 400));

      await tester.enterText(find.byKey(const ValueKey('lan-addresses')), '8.8.8.8');
      await tester.tap(find.text(appL10n.commonSave));
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text(appL10n.remoteLanErrAddress), findsOneWidget);

      await tester.enterText(find.byKey(const ValueKey('lan-addresses')), '10.8.0.2\n192.168.1.10:47821');
      await tester.tap(find.text(appL10n.commonSave));
      for (var i = 0; i < 6; i++) {
        await tester.pump(const Duration(milliseconds: 60));
      }
      final host = container.read(lanHostsProvider.notifier).byId(_hostId)!;
      expect(host.addresses.map((a) => '$a'), ['10.8.0.2:47821', '192.168.1.10:47821']);
    });
  });
}
