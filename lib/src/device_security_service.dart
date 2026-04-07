/// Device integrity check — detects rooted (Android) or jailbroken (iOS) devices.
///
/// The concrete [SafeDeviceSecurityService] delegates to the `safe_device`
/// package. An abstract interface is exposed so tests can inject a fake
/// without touching platform channels.
library;

import 'device_security_service_mobile.dart'
    if (dart.library.html) 'device_security_service_web.dart';

// ── Abstract interface ────────────────────────────────────────────────────────

abstract class DeviceSecurityService {
  /// Returns `true` when the device appears to be rooted (Android) or
  /// jailbroken (iOS). Returns `false` on failure so that a platform-channel
  /// error never blocks the user (fail-open / soft warning only).
  Future<bool> isDeviceCompromised();
}

// ── Production implementation ─────────────────────────────────────────────────

class SafeDeviceSecurityService implements DeviceSecurityService {
  const SafeDeviceSecurityService();

  @override
  Future<bool> isDeviceCompromised() => checkDeviceCompromised();
}
