/// Deep-link input validation.
///
/// Validates and sanitizes incoming deep-link URIs before any routing
/// logic runs. All callers (stream listener, initial-link handler,
/// notification tap handler, QR scanner) must pass the URI through
/// [DeepLinkValidator.validate] and discard it if the result is null.
///
/// Protections applied:
/// - Scheme + host whitelist (`{quiz,challenge,import}`)
/// - Path-traversal rejected: `quiz` and `import` allow no path segments;
///   `challenge` requires exactly one valid room-code segment.
///   Dart's [Uri] parser normalises `%2e%2e` → `..` in path segments, so
///   checking decoded segments covers both raw and percent-encoded variants.
/// - Per-host parameter whitelist (unknown params are ignored, not forwarded)
/// - `wordId`:  ≤128 chars, alphanumeric + `-_` only
/// - `roomCode`: exactly 6 chars, `[A-Z0-9]` after normalisation
/// - `name`:    ≤200 chars, C0/C1 control characters stripped
/// - `data`:    ≤500 KB (base64 length), base64url charset only
library;

/// Parsed, validated representation of a deep link.
///
/// Callers switch on [type] to retrieve the relevant typed fields.
final class ValidatedDeepLink {
  const ValidatedDeepLink._({
    required this.type,
    this.wordId,
    this.roomCode,
    this.name,
    this.data,
  });

  // ignore: prefer_constructors_over_static_methods
  static ValidatedDeepLink _quiz({String? wordId}) =>
      ValidatedDeepLink._(type: DeepLinkType.quiz, wordId: wordId);

  // ignore: prefer_constructors_over_static_methods
  static ValidatedDeepLink _challenge({required String roomCode}) =>
      ValidatedDeepLink._(type: DeepLinkType.challenge, roomCode: roomCode);

  // ignore: prefer_constructors_over_static_methods
  static ValidatedDeepLink _import({required String name, required String data}) =>
      ValidatedDeepLink._(type: DeepLinkType.import, name: name, data: data);

  /// The type of action this link represents.
  final DeepLinkType type;

  /// `{scheme}://quiz?wordId=…` — may be null (open any eligible project).
  final String? wordId;

  /// `{scheme}://challenge/{roomCode}` — exactly 6 chars, uppercase.
  final String? roomCode;

  /// `{scheme}://import?name=…` — sanitised project name (never null for import).
  final String? name;

  /// `{scheme}://import?data=…` — raw base64url payload (never null for import).
  final String? data;
}

/// Discriminator for [ValidatedDeepLink].
enum DeepLinkType { quiz, challenge, import }

/// Stateless validator for deep-link URIs.
///
/// The [scheme] parameter is configurable (defaults to `'vocabapp'`).
abstract final class DeepLinkValidator {
  // ── Limits ──────────────────────────────────────────────────────────────────
  static const int _maxDataLength = 500 * 1024; // base64 chars ≈ 375 KB binary
  static const int _maxNameLength = 200;
  static const int _maxWordIdLength = 128;

  // ── Patterns ─────────────────────────────────────────────────────────────────
  static const Set<String> _allowedHosts = {'quiz', 'challenge', 'import'};

  static final RegExp _wordIdPattern = RegExp(r'^[A-Za-z0-9_\-]+$');
  static final RegExp _roomCodePattern = RegExp(r'^[A-Z0-9]{6}$');

  // Base64url + standard base64 padding chars
  static final RegExp _base64UrlPattern = RegExp(r'^[A-Za-z0-9+/=_\-]*$');

  /// Returns a [ValidatedDeepLink] when [uri] passes all checks, or null.
  ///
  /// Callers should silently discard null results — no error UI is shown for
  /// invalid deep links (graceful fallback).
  ///
  /// The [scheme] parameter (default: `'vocabapp'`) controls which URI scheme
  /// is accepted. Note: Dart normalises URI schemes to lowercase on parse, so
  /// the comparison is case-insensitive in practice.
  static ValidatedDeepLink? validate(Uri uri, {String scheme = 'vocabapp'}) {
    // 1. Scheme whitelist (Dart normalises scheme to lowercase on parse)
    if (uri.scheme != scheme.toLowerCase()) return null;

    // 2. Host whitelist
    if (!_allowedHosts.contains(uri.host)) return null;

    // 3. Per-host validation (path-traversal is enforced per-host via strict
    //    path-segment rules; Dart decodes %2e%2e → ".." in pathSegments)
    return switch (uri.host) {
      'quiz' => _validateQuiz(uri),
      'challenge' => _validateChallenge(uri),
      'import' => _validateImport(uri),
      _ => null,
    };
  }

  // ── Per-host validators ───────────────────────────────────────────────────

  static ValidatedDeepLink? _validateQuiz(Uri uri) {
    // quiz takes no path segments: {scheme}://quiz?wordId=...
    if (uri.pathSegments.isNotEmpty) return null;
    final wordId = uri.queryParameters['wordId'];
    if (wordId != null) {
      if (wordId.isEmpty || wordId.length > _maxWordIdLength) return null;
      if (!_wordIdPattern.hasMatch(wordId)) return null;
    }
    return ValidatedDeepLink._quiz(wordId: wordId);
  }

  static ValidatedDeepLink? _validateChallenge(Uri uri) {
    // Expect exactly one path segment: {scheme}://challenge/XXXXXX
    final segments = uri.pathSegments;
    if (segments.length != 1) return null;
    final code = segments.first.toUpperCase();
    if (!_roomCodePattern.hasMatch(code)) return null;
    return ValidatedDeepLink._challenge(roomCode: code);
  }

  static ValidatedDeepLink? _validateImport(Uri uri) {
    // import takes no path segments: {scheme}://import?data=...&name=...
    // Dart normalises %2e%2e to ".." in pathSegments, so this check also
    // rejects path-traversal attempts.
    if (uri.pathSegments.isNotEmpty) return null;

    final data = uri.queryParameters['data'];
    if (data == null || data.isEmpty) return null;

    // Size limit (checked before any decoding to prevent DoS)
    if (data.length > _maxDataLength) return null;

    // Base64url character whitelist (also rejects decoded null bytes)
    if (!_base64UrlPattern.hasMatch(data)) return null;

    final name = _sanitiseName(uri.queryParameters['name'] ?? '');
    return ValidatedDeepLink._import(name: name, data: data);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  /// Strips ASCII control characters and trims whitespace; falls back to
  /// `'Imported'` when the result is empty; truncates at [_maxNameLength].
  static String _sanitiseName(String raw) {
    // Remove C0/C1 control characters and null bytes
    final cleaned = raw
        .replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f]'), '')
        .trim();
    if (cleaned.isEmpty) return 'Imported';
    return cleaned.length > _maxNameLength
        ? cleaned.substring(0, _maxNameLength)
        : cleaned;
  }
}
