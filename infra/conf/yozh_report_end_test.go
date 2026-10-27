package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestReportEndTravelsFromJSONToTheRule(t *testing.T) {
	for _, tc := range []struct {
		name, webhook string
		want          bool
	}{
		{"on", `{"url":"http://127.0.0.1:9/e","reportEnd":true}`, true},
		{"absent", `{"url":"http://127.0.0.1:9/e"}`, false},
		{"off", `{"url":"http://127.0.0.1:9/e","reportEnd":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg conf.RouterConfig
			raw := `{"rules":[{"inboundTag":["in"],"outboundTag":"direct","ruleTag":"main","webhook":` + tc.webhook + `}]}`
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				t.Fatal(err)
			}
			built, err := cfg.Build()
			if err != nil {
				t.Fatal(err)
			}
			if got := built.Rule[0].GetWebhook().GetReportEnd(); got != tc.want {
				t.Fatalf("ReportEnd = %v, want %v", got, tc.want)
			}
		})
	}
}
