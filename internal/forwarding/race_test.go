//go:build race

package forwarding_test

// The race detector drops pooled buffers at random, so allocation counts vary.
const raceEnabled = true
