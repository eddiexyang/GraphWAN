//go:build !linux

package streamproxy

// SendBuffer is the most a session end keeps where the kernel's largest
// send buffer is unknown.
func SendBuffer() uint64 { return defaultSendBuffer }
