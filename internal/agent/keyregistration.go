package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// keyRegistration completes the registration of an Agent that an operator
// added by public key. The controller identifies it by a signature from its
// key and returns what enrollment would have, without a certificate.
func (c *Client) keyRegistration(ctx context.Context) (*Registration, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, "GET", c.server+model.AgentRegistrationPath, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &challengeSigner{base: c.transport, key: c.cache.PrivateKey(), byKey: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register by public key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("registration by public key rejected: HTTP %d; add this Agent's public key on the controller, or enroll it with a token", resp.StatusCode)
	}
	var result struct {
		CA        []byte                 `json:"ca_certificate"`
		Directory *model.ServerDirectory `json:"servers"`
		AgentID   model.ID               `json:"agent_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSnapshotBytes)).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.CA) == 0 || !x509.NewCertPool().AppendCertsFromPEM(result.CA) {
		return nil, errors.New("registration response has no valid controller CA")
	}
	if result.Directory != nil && string(result.Directory.CA) != string(result.CA) {
		return nil, errors.New("registration response directory has a different CA")
	}
	reg := &Registration{CA: result.CA, Transport: c.options.ServerTransport, Directory: result.Directory, AgentID: result.AgentID, Server: c.server}
	if err := c.cache.SaveRegistration(*reg); err != nil {
		return nil, err
	}
	c.options.Logger.Info("agent registered by public key", "agent_id", reg.AgentID, "server", reg.Server)
	return reg, nil
}
