import 'package:safe_device/safe_device.dart';

Future<bool> checkDeviceCompromised() async {
  try {
    return await SafeDevice.isJailBroken;
  } catch (_) {
    return false;
  }
}
