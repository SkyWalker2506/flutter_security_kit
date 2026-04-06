/// A simple sliding-window in-memory rate limiter.
///
/// Each [RateLimiter] instance tracks one "bucket" of requests (e.g. one API
/// endpoint, or one user action type). Call [checkAndRecord] before performing
/// the operation: it returns `true` when the call is allowed (and records the
/// timestamp internally); `false` when the window is full and the caller should
/// back off.
///
/// All state is in-memory and resets on app restart — this is a best-effort
/// client-side guard, not a server-side enforcement mechanism.
library;

/// Sliding-window, in-memory rate limiter.
///
/// Example — allow at most 10 dictionary lookups per minute:
/// ```dart
/// final limiter = RateLimiter(maxRequests: 10, window: Duration(minutes: 1));
/// if (!limiter.checkAndRecord()) {
///   throw RateLimitExceededException(limiter.retryAfter);
/// }
/// ```
final class RateLimiter {
  RateLimiter({required this.maxRequests, required this.window});

  /// Maximum number of requests permitted within [window].
  final int maxRequests;

  /// The sliding-window duration.
  final Duration window;

  final List<DateTime> _timestamps = [];

  /// Checks whether a new request is allowed.
  ///
  /// Returns `true` and records the current timestamp when the request is
  /// within the limit. Returns `false` without recording when the limit is
  /// already reached.
  bool checkAndRecord() {
    _evict();
    if (_timestamps.length >= maxRequests) return false;
    _timestamps.add(DateTime.now());
    return true;
  }

  /// The number of requests remaining in the current window.
  int get remaining {
    _evict();
    return (maxRequests - _timestamps.length).clamp(0, maxRequests);
  }

  /// How long the caller must wait until the next request will be allowed.
  ///
  /// Returns [Duration.zero] when the limit has not been reached.
  Duration get retryAfter {
    _evict();
    if (_timestamps.length < maxRequests) return Duration.zero;
    final expiry = _timestamps.first.add(window);
    final wait = expiry.difference(DateTime.now());
    return wait.isNegative ? Duration.zero : wait;
  }

  /// Clears all recorded timestamps. Useful for testing or explicit resets.
  void reset() => _timestamps.clear();

  // Remove timestamps that have fallen outside the current window.
  void _evict() {
    final cutoff = DateTime.now().subtract(window);
    _timestamps.removeWhere((t) => t.isBefore(cutoff));
  }
}

/// Thrown (or returned as a signal) when a [RateLimiter] denies a request.
final class RateLimitExceededException implements Exception {
  const RateLimitExceededException(this.retryAfter);

  /// Approximate time to wait before retrying. May be [Duration.zero].
  final Duration retryAfter;

  @override
  String toString() =>
      'RateLimitExceededException(retryAfter: $retryAfter)';
}
