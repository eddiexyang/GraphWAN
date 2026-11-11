package agent

import (
	"github.com/eWloYW8/GraphWAN/internal/model"
	"reflect"
	"time"
)

// Idle resource/RTT samples and user-data counters ride on the periodic
// report. Configuration, errors, link transitions and link-state route changes
// still trigger the next two-second tick.
func reportChanged(previous, next model.AgentReport) bool {
	if !reflect.DeepEqual(previous.Update, next.Update) || previous.Version != next.Version || previous.AppliedRevision != next.AppliedRevision || previous.RoutingHash != next.RoutingHash || previous.ConfigError != next.ConfigError || previous.RuntimeError != next.RuntimeError || len(previous.Links) != len(next.Links) {
		return true
	}
	if (previous.LinkState == nil) != (next.LinkState == nil) || next.LinkState != nil && previous.LinkState.RouteHash != next.LinkState.RouteHash {
		return true
	}
	old := make(map[string]model.LinkStatus, len(previous.Links))
	for _, link := range previous.Links {
		idleLinkMetrics(&link)
		old[link.LinkID] = link
	}
	for _, link := range next.Links {
		idleLinkMetrics(&link)
		if prior, ok := old[link.LinkID]; !ok || prior != link {
			return true
		}
	}
	return false
}

// withoutRoutes takes the installed routes out of a report, which carries
// them only when they changed, and returns them.
func withoutRoutes(r *model.AgentReport) map[model.ID][]model.Route {
	if r.LinkState == nil {
		return nil
	}
	ls := *r.LinkState
	routes := ls.Routes
	ls.Routes = nil
	r.LinkState = &ls
	return routes
}

// routedReport attaches the installed routes to a full report when they
// differ from those last sent on the connection, and returns the route hash
// the controller holds routes for once it is sent.
func routedReport(report model.AgentReport, routes map[model.ID][]model.Route, sent string) (model.AgentReport, string) {
	ls := report.LinkState
	if ls == nil || ls.RouteHash == sent {
		return report, sent
	}
	with := *ls
	with.Routes = routes
	report.LinkState = &with
	return report, ls.RouteHash
}

func idleLinkMetrics(link *model.LinkStatus) {
	link.RTTMillis, link.Loss, link.RTTMeasuredAt, link.LastHandshake = 0, 0, time.Time{}, time.Time{}
	link.RXBytes, link.TXBytes = 0, 0
}
