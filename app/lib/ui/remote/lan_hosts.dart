import 'dart:async';

import 'package:dsh_remote/dsh_remote.dart' show LocalPairingLink, formatFingerprint, identityFingerprint;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/l10n.dart';
import '../../state/connection_state.dart';
import '../../state/hosts_state.dart';
import '../common/app_dialog.dart';
import '../common/status_chip.dart';
import '../settings/settings_widgets.dart';
import '../theme/app_icons.dart';
import '../theme/theme.dart';
import 'host_status.dart';
import 'network_details_sheet.dart';

/// 局域网主机: Hosts paired by QR code (ds-harness-remote Local Direct),
/// reached straight over a private network.
class LanHostsSection extends ConsumerWidget {
  const LanHostsSection({super.key, required this.onUse});

  final ValueChanged<HostRef> onUse;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final hosts = ref.watch(lanHostsProvider).value ?? const <LocalPairedHost>[];
    final active = ref.watch(activeHostProvider);
    return SettingsSection(
      title: l10n.remoteLanHosts,
      footer: Text(l10n.remoteLanFooter),
      children: [
        for (final h in hosts)
          _LanRow(
            host: h,
            active: active == HostRef.lan(h.hostDeviceId),
            onTap: () => onUse(HostRef.lan(h.hostDeviceId, name: h.name)),
            onEdit: () => unawaited(_editHost(context, ref, h)),
          ),
        SettingsTile(
          key: const ValueKey('lan-pair'),
          icon: AppIcons.add,
          tinted: false,
          spot: Spots.pairLanHost,
          onTap: () => unawaited(_pair(context, ref)),
        ),
      ],
    );
  }

  Future<void> _pair(BuildContext context, WidgetRef ref) async {
    final paired = await showLanPairing(context);
    if (paired != null) onUse(HostRef.lan(paired.hostDeviceId, name: paired.name));
  }
}

/// Pairs with a Host from its `dshremote://local-pair` link ([initialLink]
/// from a scanned QR code, or pasted). The Host's name, fingerprint and
/// addresses from the link are shown for checking against `local pair` on
/// the computer, and nothing connects before the person taps 配对: any web
/// page can open such a link. Returns the paired Host.
Future<LocalPairedHost?> showLanPairing(BuildContext context, {String? initialLink}) => showAppDialog<LocalPairedHost>(
  context: context,
  barrierDismissible: false,
  builder: (_) => _PairDialog(initialLink: initialLink),
);

Future<void> _editHost(BuildContext context, WidgetRef ref, LocalPairedHost host) => showAppDialog<void>(
  context: context,
  builder: (_) => _EditDialog(host: host),
);

class _LanRow extends ConsumerWidget {
  const _LanRow({required this.host, required this.active, required this.onTap, required this.onEdit});

  final LocalPairedHost host;
  final bool active;
  final VoidCallback onTap;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final hostRef = HostRef.lan(host.hostDeviceId, name: host.name);
    final status = active ? ref.watch(hostLinkStatusProvider(hostRef)).value : null;
    return Semantics(
      key: ValueKey('lan-row-${host.hostDeviceId}'),
      selected: active,
      inMutuallyExclusiveGroup: true,
      child: SettingsTile(
        icon: hostKindIcon(HostKind.lan),
        tinted: false,
        title: host.name,
        subtitle: host.addresses.isEmpty ? host.fingerprint : '${host.addresses.first}',
        onTap: onTap,
        value: status == null
            ? null
            : status.isConnected
            ? TextButton.icon(
                onPressed: () => showRemoteNetworkDetails(context, hostRef),
                icon: const Icon(AppIcons.info, size: 16),
                label: Text(l10n.remotePathLocalDirect),
              )
            : Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  AnimatedStatusDot(tone: HostStatusView.ofLink(status).tone, size: 7),
                  const SizedBox(width: 6),
                  Text(HostStatusView.ofLink(status).label),
                ],
              ),
        trailing: IconButton(
          tooltip: l10n.commonEdit,
          visualDensity: VisualDensity.compact,
          color: DshColors.of(context).textTertiary,
          icon: const Icon(AppIcons.configure, size: 20),
          onPressed: onEdit,
        ),
      ),
    );
  }
}

class _PairDialog extends ConsumerStatefulWidget {
  const _PairDialog({this.initialLink});

  final String? initialLink;

  @override
  ConsumerState<_PairDialog> createState() => _PairDialogState();
}

class _PairDialogState extends ConsumerState<_PairDialog> {
  late final TextEditingController _link = TextEditingController(text: widget.initialLink ?? '');
  bool _busy = false;
  String? _error;
  LocalPairingLink? _parsed;

  @override
  void initState() {
    super.initState();
    _parsed = LocalPairingLink.tryParse(_link.text);
    // Every edit: the preview must show exactly what 配对 would use (name and addresses included).
    _link.addListener(() => setState(() => _parsed = LocalPairingLink.tryParse(_link.text)));
  }

  @override
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim();
    if (text != null && text.isNotEmpty && mounted) setState(() => _link.text = text);
  }

  Future<void> _submit() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final paired = await ref.read(lanHostsProvider.notifier).pair(_link.text.trim());
      if (!mounted) return;
      ScaffoldMessenger.maybeOf(context)
          ?.showSnackBar(SnackBar(content: Text(context.l10n.remoteLanPaired(paired.name))));
      Navigator.pop(context, paired);
    } on HostLinkError catch (e) {
      if (mounted) setState(() => _error = e.message);
    } catch (_) {
      if (mounted) setState(() => _error = context.l10n.commonConnectionFailed);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final colors = DshColors.of(context);
    return AlertDialog(
      // The preview plus the keyboard can be taller than the screen.
      scrollable: true,
      title: Text(l10n.remoteLanAdd),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(l10n.remoteLanPairHelp, style: TextStyle(color: colors.textTertiary)),
          if (_parsed case final link?) ...[const SizedBox(height: 12), _LinkPreview(link: link)],
          const SizedBox(height: 12),
          TextField(
            key: const ValueKey('lan-pair-link'),
            controller: _link,
            enabled: !_busy,
            minLines: 2,
            maxLines: 4,
            autocorrect: false,
            enableSuggestions: false,
            keyboardType: TextInputType.url,
            decoration: InputDecoration(
              labelText: l10n.remoteLanPairLinkLabel,
              hintText: 'dshremote://local-pair?…',
              errorText: _error,
              errorMaxLines: 3,
              suffixIcon: IconButton(
                tooltip: l10n.commonPaste,
                icon: const Icon(AppIcons.paste, size: 20),
                onPressed: _busy ? null : _paste,
              ),
            ),
          ),
        ],
      ),
      actions: [
        TextButton(onPressed: _busy ? null : () => Navigator.pop(context), child: Text(l10n.commonCancel)),
        FilledButton(
          onPressed: _busy ? null : _submit,
          child: _busy
              ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : Text(l10n.remoteLanPair),
        ),
      ],
    );
  }
}

class _EditDialog extends ConsumerStatefulWidget {
  const _EditDialog({required this.host});

  final LocalPairedHost host;

  @override
  ConsumerState<_EditDialog> createState() => _EditDialogState();
}

class _EditDialogState extends ConsumerState<_EditDialog> {
  late final TextEditingController _addresses = TextEditingController(
    text: widget.host.addresses.map((a) => '$a').join('\n'),
  );
  String? _error;

  @override
  void dispose() {
    _addresses.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final l10n = context.l10n;
    final lines = _addresses.text.split(RegExp(r'[\s,]+')).where((l) => l.isNotEmpty).toList();
    final List<LocalAddress> parsed;
    try {
      parsed = [for (final line in lines) LocalAddress.parseInput(line)];
    } on FormatException {
      setState(() => _error = l10n.remoteLanErrAddress);
      return;
    }
    if (parsed.isEmpty || parsed.length > 8) {
      setState(() => _error = l10n.remoteLanErrAddress);
      return;
    }
    try {
      await ref.read(lanHostsProvider.notifier).setAddresses(widget.host.hostDeviceId, parsed);
      if (mounted) Navigator.pop(context);
    } on HostLinkError catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  Future<void> _forget() async {
    final l10n = context.l10n;
    final navigator = Navigator.of(context);
    final ok = await showAppDialog<bool>(
      context: context,
      builder: (dialog) => AlertDialog(
        title: Text(l10n.remoteLanForgetTitle(widget.host.name)),
        content: Text(l10n.remoteLanForgetBody),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dialog, false), child: Text(l10n.commonCancel)),
          FilledButton(onPressed: () => Navigator.pop(dialog, true), child: Text(l10n.remoteLanForget)),
        ],
      ),
    );
    if (ok != true) return;
    await ref.read(lanHostsProvider.notifier).forget(widget.host.hostDeviceId);
    if (navigator.mounted) navigator.pop();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final colors = DshColors.of(context);
    return AlertDialog(
      title: Text(widget.host.name),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SelectableText(widget.host.fingerprint, style: TextStyle(color: colors.textTertiary)),
          const SizedBox(height: 12),
          TextField(
            key: const ValueKey('lan-addresses'),
            controller: _addresses,
            minLines: 2,
            maxLines: 6,
            autocorrect: false,
            enableSuggestions: false,
            keyboardType: TextInputType.multiline,
            decoration: InputDecoration(
              labelText: l10n.remoteLanAddresses,
              hintText: l10n.remoteLanAddressesHint,
              errorText: _error,
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          style: TextButton.styleFrom(foregroundColor: colors.danger),
          onPressed: _forget,
          child: Text(l10n.remoteLanForget),
        ),
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.commonCancel)),
        FilledButton(onPressed: _save, child: Text(l10n.commonSave)),
      ],
    );
  }
}

/// What a pairing link says about its Host, to check against the computer's
/// `local pair` output before anything connects.
class _LinkPreview extends StatelessWidget {
  const _LinkPreview({required this.link});

  final LocalPairingLink link;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final theme = Theme.of(context);
    final colors = DshColors.of(context);
    return Column(
      key: const ValueKey('lan-pair-preview'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(link.name ?? l10n.commonRemoteHost, style: theme.textTheme.titleMedium),
        const SizedBox(height: 2),
        SelectableText(
          l10n.remoteLanFingerprint(formatFingerprint(identityFingerprint(link.hostIdentityKey))),
          style: AppType.tabular(theme.textTheme.bodyMedium!),
        ),
        Text(link.addresses.join(' · '), style: theme.textTheme.bodySmall?.copyWith(color: colors.textTertiary)),
        const SizedBox(height: 6),
        Text(l10n.remoteLanCheckFingerprint, style: theme.textTheme.bodySmall?.copyWith(color: colors.textTertiary)),
      ],
    );
  }
}
