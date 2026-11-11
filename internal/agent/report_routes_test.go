package agent

import (
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// The installed routes go to the controller with the first report of a
// connection and after each change, and not with unchanged reports.
func TestReportCarriesRoutesWhenTheyChange(t *testing.T) {
	routes := map[model.ID][]model.Route{"n": {{Destination: "b", NextHop: "b", Cost: 1}}}
	report := func(hash string) model.AgentReport {
		return model.AgentReport{LinkState: &model.LinkStateReport{RouteHash: hash, Routes: routes}}
	}
	r := report("h1")
	got := withoutRoutes(&r)
	if r.LinkState.Routes != nil || got == nil {
		t.Fatal("the routes stayed in the report compared for changes")
	}
	out, sent := routedReport(r, got, "")
	if out.LinkState.Routes == nil || sent != "h1" {
		t.Fatal("the first report of a connection left out the routes")
	}
	r = report("h1")
	got = withoutRoutes(&r)
	if out, sent = routedReport(r, got, sent); out.LinkState.Routes != nil || sent != "h1" {
		t.Fatal("an unchanged report carried the routes again")
	}
	r = report("h2")
	got = withoutRoutes(&r)
	if out, sent = routedReport(r, got, sent); out.LinkState.Routes == nil || sent != "h2" {
		t.Fatal("changed routes were not sent")
	}
	if out, sent = routedReport(model.AgentReport{}, nil, sent); out.LinkState != nil || sent != "h2" {
		t.Fatal("a report without link-state changed")
	}
}
