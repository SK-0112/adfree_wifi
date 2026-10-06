#pragma once
// Single source of truth for the firmware version. tools/build_release.py reads
// it from here, and the OTA check compares the manifest against it. It is a
// compile-time constant on purpose: a version stored in config.json would go
// stale the moment someone reflashed over USB.
#define ADFREE_FW_VERSION "1.1.0"
