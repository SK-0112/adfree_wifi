#pragma once
#include <Arduino.h>

class WifiMgr {
public:
  // Tries to connect using saved credentials. If that fails (or none saved),
  // starts a SoftAP + captive setup portal and BLOCKS forever inside this
  // call, serving the portal until the user submits new credentials, at
  // which point it saves them and reboots. Returns true only on a
  // successful STA connection without needing the portal.
  static bool begin();

  static bool isConnected();
  static bool isPortalActive();

  // Per-device setup-hotspot credentials. The password is generated from the
  // hardware RNG on first use and persisted, so it is unique to this board and
  // cannot be derived from anything an attacker can observe. Both are safe to
  // call before the portal has ever run.
  static String apSsid();
  static String apPassword();

  // Call every loop() iteration during normal (non-portal) operation.
  static void loop();

private:
  static void runPortal();
  static bool tryConnectSTA(uint32_t timeoutMs);
};
