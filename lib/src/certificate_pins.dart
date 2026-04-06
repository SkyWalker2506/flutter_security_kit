/// Certificate pin definitions for all pinned hosts.
///
/// ## What is pinned
///
/// Firebase and its underlying Google APIs share the Google Trust Services (GTS)
/// root CA hierarchy.  We pin at the root-CA level (not leaf/intermediate) so
/// that ordinary certificate renewals by Google never break the app.  Three GTS
/// roots are included so that if Google activates a new root during a rotation,
/// the backup pin keeps connectivity intact.
///
/// ## SHA-256 SPKI fingerprints
///
/// Each value is the SHA-256 hash of the certificate's SubjectPublicKeyInfo (SPKI)
/// DER encoding, then base64-encoded.  Extract the fingerprint for any host with:
///
/// ```
/// openssl s_client -connect <host>:443 </dev/null 2>/dev/null \
///   | openssl x509 -pubkey -noout \
///   | openssl pkey -pubin -outform DER \
///   | openssl dgst -sha256 -binary | base64
/// ```
///
/// Verify Google roots at: https://pki.goog/repository/
///
/// ## Pin rotation procedure
///
/// 1. Obtain the replacement certificate's SPKI SHA-256 fingerprint (command above).
/// 2. Add the new fingerprint as an additional entry in the relevant [PinSet.spkiSha256Pins].
/// 3. Ship the app update and wait until adoption reaches ~95 % (typically one release cycle).
/// 4. Remove the retired fingerprint.
///
/// Never reduce the list to a single pin — always keep at least one backup.
library;

/// A set of SPKI SHA-256 fingerprints for a specific host or CA hierarchy.
final class PinSet {
  const PinSet({
    required this.host,
    required this.spkiSha256Pins,
    this.includeSubdomains = true,
  });

  /// Canonical host name or domain root (e.g. `googleapis.com`).
  ///
  /// When [includeSubdomains] is true, all sub-domains are also covered.
  final String host;

  /// One or more base64-encoded SHA-256 SPKI fingerprints.
  ///
  /// At least two entries are recommended: one active, one backup for rotation.
  final List<String> spkiSha256Pins;

  /// Whether sub-domains inherit the same pin set.
  final bool includeSubdomains;
}

/// Central registry of certificate pins used across the app.
///
/// Pins are grouped by domain.  All Firebase services (Firestore, Auth,
/// Storage, Realtime Database) resolve to Google-owned domains that are
/// secured by the GTS root hierarchy below.
abstract final class CertificatePins {
  // ── Google Trust Services roots ──────────────────────────────────────────────
  //
  // Source: https://pki.goog/repository/
  //
  // GTS Root R1 (self-signed; expires 2036-06-22)
  // SHA-256 SPKI: hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Vg=
  static const String _gtsR1 = 'hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Vg=';

  // GTS Root R2 (self-signed; expires 2036-06-22) — backup
  // SHA-256 SPKI: Un6AjaPuKsP1qhQEG0PjVRlWLLt7Xc3TkJHRQOJrRXA=
  static const String _gtsR2 = 'Un6AjaPuKsP1qhQEG0PjVRlWLLt7Xc3TkJHRQOJrRXA=';

  // GTS Root R3 (self-signed; expires 2036-06-22) — backup
  // SHA-256 SPKI: ENEMTm4zhQS1tXByMITjO7OGnAQB9RORoCfCpFRkSRo=
  static const String _gtsR3 = 'ENEMTm4zhQS1tXByMITjO7OGnAQB9RORoCfCpFRkSRo=';

  // ── Pin sets ─────────────────────────────────────────────────────────────────

  /// Google APIs: Firestore, Firebase Auth, Firebase Storage.
  static const PinSet googleapis = PinSet(
    host: 'googleapis.com',
    spkiSha256Pins: [_gtsR1, _gtsR2, _gtsR3],
  );

  /// Firebase Hosting and project-specific endpoints (*.firebaseapp.com).
  static const PinSet firebaseApp = PinSet(
    host: 'firebaseapp.com',
    spkiSha256Pins: [_gtsR1, _gtsR2, _gtsR3],
  );

  /// Firebase Realtime Database (*.firebaseio.com).
  static const PinSet firebaseIo = PinSet(
    host: 'firebaseio.com',
    spkiSha256Pins: [_gtsR1, _gtsR2, _gtsR3],
  );

  /// All Firebase-related pin sets.
  static const List<PinSet> firebase = [googleapis, firebaseApp, firebaseIo];

  /// Every active pin set in the application.
  static const List<PinSet> all = [...firebase];
}
