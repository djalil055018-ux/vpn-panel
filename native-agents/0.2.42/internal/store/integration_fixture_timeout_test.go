//go:build integration

package store

import (
 "os"
 "time"
)

// Root fixture setup has substantial crypto/SQL work under CPU-capped QEMU
// TCG. Ordinary test deadlines stay identical. Only this explicit synthetic
// harness opt-in extends root setup lifetime; product and short operation
// deadlines, assertions, isolation checks and lock tests are unchanged.
func fixtureTimeout(original time.Duration) time.Duration {
 if os.Getenv("PAUK_TEST_SLOW_EMULATOR")=="1" {return original*5}
 return original
}
