// A LAN host's pairing QR code (ds-harness-remote Local Direct):
// `dshremote://local-pair?v=1&id=…&k=…&a=…&c=…`, opened by the camera or any
// scanner. It pre-fills the pairing dialog; nothing pairs without a tap,
// since any web page can open such a link.

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/hosts_state.dart';
import '../ui/remote/lan_hosts.dart' show showLanPairing;
import 'app_links.dart';

const lanPairLinkScheme = 'dshremote';

VoidCallback registerLanPairLinks(LinkRouter router) => router.registerLinkHandler('local-pair', (uri) async {
  if (uri.scheme.toLowerCase() != lanPairLinkScheme) return false;
  final context = router.context;
  if (context == null) return false;
  final container = ProviderScope.containerOf(context, listen: false);
  final paired = await showLanPairing(context, initialLink: uri.toString());
  if (paired != null) {
    container.read(activeHostProvider.notifier).select(HostRef.lan(paired.hostDeviceId, name: paired.name));
  }
  return true;
});
