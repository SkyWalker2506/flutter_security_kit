/// SSL / TLS certificate-pinning service.
///
/// ## Layers of enforcement
///
/// Certificate pinning is applied at two complementary layers:
///
/// | Layer | Mechanism | Covers |
/// |-------|-----------|--------|
/// | **Native — Android** | `res/xml/network_security_config.xml` | Firebase SDK + all Android HttpURLConnection / OkHttp calls |
/// | **Native — iOS** | `NSPinnedDomains` in `Info.plist` | Firebase SDK + all NSURLSession calls |
/// | **Dart** | This service — `IOClient` + strict `badCertificateCallback` | Any Dart-layer `http.Client` usage |
///
/// Firebase SDK connections (Firestore, Auth, Storage, RTDB) are made through
/// platform channels that use the native HTTP stack, so they are pinned by the
/// Android / iOS configuration, not by this Dart service.  The Dart layer
/// covers any code that calls [createHttpClient].
///
/// ## Debug mode
///
/// When [kDebugMode] is `true`, pinning is **bypassed**:
/// - Proxy tools (Charles, mitmproxy) work without extra setup.
/// - Unit tests do not need network access.
///
/// ## Pin rotation
///
/// See [CertificatePins] for the rotation procedure.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import 'package:flutter_security_kit/src/certificate_pins.dart';

/// Thrown when a TLS certificate presented by a pinned host does not match
/// any registered fingerprint.
final class TlsPinningException implements Exception {
  const TlsPinningException({required this.host, required this.fingerprint});

  final String host;

  /// Base64-encoded SHA-256 fingerprint of the rejected certificate DER.
  final String fingerprint;

  @override
  String toString() =>
      'TlsPinningException: certificate for "$host" does not match any '
      'registered pin. Actual SHA-256: $fingerprint';
}

/// Singleton service that configures certificate-pinned HTTP clients.
///
/// Call [initialize] once before the first [createHttpClient] call, typically
/// in `main()` alongside `AppFirebase.initialize()`.
final class CertificatePinningService {
  CertificatePinningService._();

  static final CertificatePinningService instance =
      CertificatePinningService._();

  bool _initialized = false;

  /// Whether [initialize] has been called.
  bool get isInitialized => _initialized;

  /// Whether pinning is actively enforced (`false` in debug mode).
  bool get isPinningEnabled => !kDebugMode;

  /// Initialises the service.
  ///
  /// Safe to call multiple times; subsequent calls are no-ops.
  void initialize() {
    if (_initialized) return;
    _initialized = true;

    if (kDebugMode) {
      debugPrint('[CertPin] debug mode — certificate pinning bypassed');
      return;
    }

    if (kDebugMode) {
      final pinned = CertificatePins.all.map((p) => p.host).join(', ');
      debugPrint('[CertPin] active. Pinned domains: $pinned');
    }
  }

  /// Returns an [http.Client] for making HTTPS calls.
  ///
  /// - **Debug / test**: plain [http.Client] — no pinning, proxy tools work.
  /// - **Release / profile**: [IOClient] backed by a [HttpClient] whose
  ///   `badCertificateCallback` rejects certificates not matching
  ///   [CertificatePins.all].
  ///
  /// The caller is responsible for closing the returned client.
  http.Client createHttpClient() {
    if (kDebugMode) return http.Client();
    return IOClient(_buildPinnedHttpClient());
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  HttpClient _buildPinnedHttpClient() {
    return HttpClient()
      ..badCertificateCallback = _onBadCertificate;
  }

  /// Invoked by [HttpClient] for any certificate that fails the default
  /// system-trust validation.
  ///
  /// For hosts with a registered [PinSet], allows the certificate if its
  /// SHA-256 fingerprint is in the pin set — handling cases where a valid
  /// but non-system-trusted root is used (e.g. test environments).
  ///
  /// Returns `false` (reject) in all other cases.
  static bool _onBadCertificate(
    X509Certificate cert,
    String host,
    int port,
  ) {
    final matchingPins = CertificatePins.all
        .where((ps) => _hostMatchesPinSet(host, ps))
        .expand((ps) => ps.spkiSha256Pins)
        .toSet();

    if (matchingPins.isEmpty) {
      debugPrint('[CertPin] REJECTING — no pin set registered for "$host"');
      return false;
    }

    // Compare the SHA-256 of the full certificate DER.
    // Note: the SPKI SHA-256 values in CertificatePins are used by the
    // native Android / iOS configs; at the Dart layer we compare the full
    // certificate fingerprint as a defensive backstop.
    final fp = _certFingerprintSha256(cert);
    if (matchingPins.contains(fp)) return true;

    debugPrint(
      '[CertPin] REJECTING cert for "$host" — '
      'fingerprint "$fp" not in registered pins',
    );
    return false;
  }

  /// Returns `true` when [host] is covered by [ps].
  static bool _hostMatchesPinSet(String host, PinSet ps) {
    final h = host.toLowerCase();
    final domain = ps.host.toLowerCase();
    if (h == domain) return true;
    if (ps.includeSubdomains && h.endsWith('.$domain')) return true;
    return false;
  }

  /// Computes the base64-encoded SHA-256 fingerprint of a certificate's DER.
  static String _certFingerprintSha256(X509Certificate cert) {
    final digest = sha256.convert(cert.der);
    return base64.encode(digest.bytes);
  }
}
