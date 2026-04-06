/// Flutter Security Kit — production security toolkit.
///
/// Exports:
/// - [CertificatePinningService] — SSL/TLS certificate pinning
/// - [CertificatePins] / [PinSet] — pin definitions
/// - [DeepLinkValidator] / [ValidatedDeepLink] / [DeepLinkType] — deep-link validation
/// - [DeviceSecurityService] / [SafeDeviceSecurityService] — device integrity check
/// - [RateLimiter] / [RateLimitExceededException] — sliding-window rate limiting
/// - [SuspiciousActivityTracker] / [SuspiciousEvent] / [SuspiciousEventType] / [SuspiciousActivityConfig] / [SecurityErrorReporter] — activity tracking
library;

export 'src/certificate_pinning_service.dart';
export 'src/certificate_pins.dart';
export 'src/deep_link_validator.dart';
export 'src/device_security_service.dart';
export 'src/rate_limiter.dart';
export 'src/suspicious_activity_tracker.dart';
