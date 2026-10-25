#pragma once

// Fixed privileged programs and every parent directory must be root-owned and non-writable.
bool trustedLinuxExecutable(const char *path, bool setuidAllowed = false);
