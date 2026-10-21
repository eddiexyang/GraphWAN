package model

// Agents behind a TLS-terminating gateway have no client certificate at the
// controller. They instead sign a single-use controller challenge with the
// same enrolled Ed25519 key, carried in these headers.
const (
	AgentIDHeader        = "X-GraphWAN-Agent"
	AgentChallengeHeader = "X-GraphWAN-Challenge"
	AgentSignatureHeader = "X-GraphWAN-Signature"
	AgentChallengePath   = "/api/v1/agent/challenge"
)

// AgentChallengeMessage is the exact byte string an Agent signs. The prefix
// keeps these signatures distinct from any other use of the Agent key.
func AgentChallengeMessage(id ID, challenge string) []byte {
	return []byte("graphwan agent challenge v1\n" + string(id) + "\n" + challenge)
}
