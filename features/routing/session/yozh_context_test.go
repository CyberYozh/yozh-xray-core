package session_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func TestTheRoutingContextCarriesTheReportAndTheProbe(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	plain := routing_session.AsRoutingContext(ctx).(*routing_session.Context)
	if plain.Report != nil || plain.Probe {
		t.Fatalf("a context without a report: %+v", plain)
	}

	ctx, report := session.WithConnReport(ctx)
	ctx = session.ContextWithRouteProbe(ctx)
	asked := routing_session.AsRoutingContext(ctx).(*routing_session.Context)
	if asked.Report != report || !asked.Probe {
		t.Fatalf("report %v probe %v, want the report and the probe", asked.Report, asked.Probe)
	}
}
