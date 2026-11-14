package model

// DefaultSTUNServers is copied into each newly enrolled Agent's desired state.
// Returning nil leaves STUN discovery disabled unless explicitly configured.
func DefaultSTUNServers() []string {
	return nil
}
