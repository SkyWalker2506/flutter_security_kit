/// Persistent tracker for suspicious-activity events on the local device.
///
/// Events are serialised to JSON and stored in FlutterSecureStorage. When the
/// count of high-severity events reaches [SuspiciousActivityConfig.flagThreshold]
/// the account is marked as "flagged" — a flag that other parts of the app can
/// check to reduce or block XP awards.
///
/// **Important:** This is a client-side heuristic only. A motivated attacker
/// can clear app storage to reset all state. Server-side enforcement is the
/// authoritative control; this layer provides best-effort local protection and
/// optional error telemetry via [SecurityErrorReporter].
library;

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// ── Error reporter typedef ────────────────────────────────────────────────────

/// Callback for reporting non-fatal security errors (e.g. to Crashlytics).
///
/// Inject an implementation of this type into [SuspiciousActivityTracker] to
/// forward events to your error-reporting backend. Defaults to a no-op when
/// not provided.
typedef SecurityErrorReporter = void Function(
  Object error,
  StackTrace stack, {
  String? reason,
});

// ── Event types ──────────────────────────────────────────────────────────────

/// Discriminates between the kinds of suspicious behaviour we track.
enum SuspiciousEventType {
  /// Quiz completed suspiciously fast (low severity).
  quizSpeedAbuse,

  /// Perfect score + suspiciously fast completion (high severity).
  quizPerfectSpeedAbuse,

  /// A rate limit was exceeded (high severity).
  rateLimitExceeded,
}

// ── Event model ───────────────────────────────────────────────────────────────

/// A single recorded suspicious-activity event.
final class SuspiciousEvent {
  const SuspiciousEvent({
    required this.type,
    required this.timestamp,
    this.detail,
  });

  final SuspiciousEventType type;
  final DateTime timestamp;

  /// Optional free-text detail for debugging (never shown to the user).
  final String? detail;

  Map<String, dynamic> toJson() => {
        'type': type.name,
        'timestamp': timestamp.toIso8601String(),
        if (detail != null) 'detail': detail,
      };

  static SuspiciousEvent? tryFromJson(Map<String, dynamic> json) {
    try {
      return SuspiciousEvent(
        type: SuspiciousEventType.values.byName(json['type'] as String),
        timestamp: DateTime.parse(json['timestamp'] as String),
        detail: json['detail'] as String?,
      );
    } catch (_) {
      return null;
    }
  }
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration knobs for [SuspiciousActivityTracker].
final class SuspiciousActivityConfig {
  const SuspiciousActivityConfig({
    this.flagThreshold = 3,
    this.retentionDays = 30,
  });

  /// Number of *high-severity* events before the account is flagged.
  /// High-severity events are [SuspiciousEventType.quizPerfectSpeedAbuse] and
  /// [SuspiciousEventType.rateLimitExceeded].
  final int flagThreshold;

  /// Events older than this many days are pruned on the next [record] call.
  final int retentionDays;

  static const SuspiciousActivityConfig defaults = SuspiciousActivityConfig();
}

// ── Tracker ───────────────────────────────────────────────────────────────────

/// Manages persistent suspicious-activity events using [FlutterSecureStorage].
///
/// Inject via a DI container / provider. Do not construct directly in widgets.
///
/// Optional [onError] callback is called whenever a suspicious event is
/// recorded or the account is flagged — use it to forward to Crashlytics,
/// Sentry, or any other non-fatal error reporter.
class SuspiciousActivityTracker {
  SuspiciousActivityTracker(
    this._storage, {
    SuspiciousActivityConfig config = SuspiciousActivityConfig.defaults,
    SecurityErrorReporter? onError,
  })  : _config = config,
        _onError = onError;

  final FlutterSecureStorage _storage;
  final SuspiciousActivityConfig _config;
  final SecurityErrorReporter? _onError;

  static const _kEventsKey = 'security_suspicious_events';
  static const _kFlaggedKey = 'security_account_flagged';

  // ── Public API ─────────────────────────────────────────────────────────────

  /// Whether the account has been flagged for suspicious activity.
  Future<bool> get isFlagged async {
    final value = await _storage.read(key: _kFlaggedKey);
    return value == 'true';
  }

  /// All stored events (oldest first), after pruning expired entries.
  Future<List<SuspiciousEvent>> get events async {
    final raw = await _storage.read(key: _kEventsKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final list = jsonDecode(raw) as List<dynamic>;
      return list
          .map((e) {
            try {
              return SuspiciousEvent.tryFromJson(e as Map<String, dynamic>);
            } catch (_) {
              return null;
            }
          })
          .whereType<SuspiciousEvent>()
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Records a suspicious event, prunes old entries, and re-evaluates flag.
  ///
  /// When [onError] was provided to the constructor, also emits a non-fatal
  /// error event so the backend has visibility.
  Future<void> record(SuspiciousEvent event) async {
    await _pruneOld();

    final current = await _readEventJsonList();
    current.add(event.toJson());
    await _storage.write(key: _kEventsKey, value: jsonEncode(current));

    _onError?.call(
      Exception('SuspiciousActivity(${event.type.name})'),
      StackTrace.current,
      reason: event.detail,
    );

    await _evaluateFlag();
  }

  /// Clears the flagged state (e.g. after a successful appeal). Does NOT
  /// delete the event log.
  Future<void> clearFlag() => _storage.delete(key: _kFlaggedKey);

  // ── Private ────────────────────────────────────────────────────────────────

  /// Reads the raw list of event JSON maps from storage.
  Future<List<Map<String, dynamic>>> _readEventJsonList() async {
    final raw = await _storage.read(key: _kEventsKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final list = jsonDecode(raw) as List<dynamic>;
      return list.whereType<Map<String, dynamic>>().toList();
    } catch (_) {
      return [];
    }
  }

  /// Sets the flag when high-severity event count reaches the threshold.
  Future<void> _evaluateFlag() async {
    if (await isFlagged) return; // already flagged — nothing to do

    final allEvents = await events;
    final highCount = allEvents
        .where((e) =>
            e.type == SuspiciousEventType.quizPerfectSpeedAbuse ||
            e.type == SuspiciousEventType.rateLimitExceeded)
        .length;

    if (highCount >= _config.flagThreshold) {
      await _storage.write(key: _kFlaggedKey, value: 'true');
      _onError?.call(
        Exception('AccountFlagged'),
        StackTrace.current,
        reason: 'Account flagged after $highCount high-severity events',
      );
    }
  }

  /// Removes events older than [SuspiciousActivityConfig.retentionDays].
  Future<void> _pruneOld() async {
    final cutoff =
        DateTime.now().subtract(Duration(days: _config.retentionDays));
    final current = await _readEventJsonList();
    final pruned = current.where((map) {
      try {
        final ts = DateTime.parse(map['timestamp'] as String);
        return ts.isAfter(cutoff);
      } catch (_) {
        return false; // drop unparseable entries
      }
    }).toList();
    await _storage.write(key: _kEventsKey, value: jsonEncode(pruned));
  }
}
