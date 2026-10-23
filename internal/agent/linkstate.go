package agent

import (
	"time"

	"github.com/eWloYW8/GraphWAN/internal/linkstate"
	"github.com/eWloYW8/GraphWAN/internal/mesh"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// newLinkState routes from advertisements exchanged with neighbours, so
// forwarding keeps converging whether or not the controller is reachable.
func (r *DataPlane) newLinkState() *linkstate.Engine {
	r.damper = newEdgeDamper()
	return linkstate.New(linkstate.Callbacks{
		Send: func(network, peer model.ID, raw []byte) {
			if state := r.state.Load(); state != nil {
				state.mesh.SendLinkState(network, peer, raw)
			}
		},
		// An edge is usable here while it has a healthy Link, the condition
		// the Agent also reports to the controller, unless damping holds it.
		Local: func() map[model.ID]map[model.ID]bool {
			up := map[model.ID]map[model.ID]bool{}
			for _, s := range r.Report() {
				if !s.Healthy {
					continue
				}
				if up[s.NetworkID] == nil {
					up[s.NetworkID] = map[model.ID]bool{}
				}
				up[s.NetworkID][s.EdgeID] = true
			}
			return r.damper.filter(up, time.Now())
		},
		Apply: r.ApplyRoutes,
	})
}

func (r *DataPlane) linkStateHandler() mesh.LinkStateHandler {
	return mesh.LinkStateHandler{
		Ready: r.linkState.PeerReady,
		Receive: func(network, peer model.ID, raw []byte) {
			_ = r.linkState.Receive(network, peer, raw)
		},
	}
}

// LocalRouting reports whether this configuration is routed from
// link-state; controller route updates are then ignored.
func (r *DataPlane) LocalRouting() bool {
	state := r.state.Load()
	return state != nil && linkstate.Active(state.snapshot)
}

// LinkState returns the engine's state for the status command.
func (r *DataPlane) LinkState() linkstate.View {
	v := r.linkState.View()
	v.Held = r.damper.held(time.Now())
	return v
}

// LinkStateReport is reported to the controller while routing locally.
func (r *DataPlane) LinkStateReport() *model.LinkStateReport {
	if !r.LocalRouting() {
		return nil
	}
	report := r.linkState.Report()
	return &report
}
