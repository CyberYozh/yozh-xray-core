package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// yozhQueueSize bounds what a rule that reports ends holds for its worker. The packet path never
// waits for the worker: what does not fit is dropped and counted in lost.
const yozhQueueSize = 1024

// yozhIdleTimeout closes the worker's idle connection before a receiver that resets idle
// connections after 30 s does: a POST must not meet that reset, and Go does not retry a POST.
const yozhIdleTimeout = 20 * time.Second

// yozhQueue is the one queue of a rule that reports ends: its starts, routes and ends, in order,
// sent by one worker over one kept-alive connection.
type yozhQueue struct {
	once  sync.Once
	items chan yozhItem
	lost  atomic.Int64
}

type yozhItem struct {
	start *event
	end   *endEvent
}

// endEvent is the end of a dispatch: numbers only. The start carried the addresses; the end finds
// its start by conn.
type endEvent struct {
	Kind        string `json:"kind"`
	Conn        uint64 `json:"conn"`
	TsMs        int64  `json:"tsMs"`
	DurMs       int64  `json:"durMs"`
	FirstDownMs *int64 `json:"firstDownMs,omitempty"`
	LastUpMs    *int64 `json:"lastUpMs,omitempty"`
	LastDownMs  *int64 `json:"lastDownMs,omitempty"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	Error       string `json:"error,omitempty"`
	Lost        int64  `json:"lost,omitempty"`
}

// queueStart sends a start, or a route when the dispatcher asked about another destination of a
// flow, through the rule's queue.
func (h *WebhookNotifier) queueStart(ctx routing.Context, ev *event) {
	ev.Kind = "start"
	ev.TsMs = time.Now().UnixMilli()
	if sctx, ok := ctx.(*routing_session.Context); ok {
		if sctx.Probe {
			ev.Kind = "route"
		}
		if sctx.Report != nil {
			ev.Conn = sctx.Report.Conn
		}
	}
	h.enqueue(yozhItem{start: ev})
}

// FireEnd sends the end of a dispatch this rule routed. It goes after the dispatch's start: one
// queue, one worker.
func (h *WebhookNotifier) FireEnd(end routing.ConnEnd) {
	ev := &endEvent{Kind: "end", Conn: end.Conn, TsMs: end.TsMs, DurMs: end.DurMs, Up: end.Up, Down: end.Down, Error: end.Error}
	if end.FirstDownMs >= 0 {
		ev.FirstDownMs = ptr(end.FirstDownMs)
	}
	if end.LastUpMs >= 0 {
		ev.LastUpMs = ptr(end.LastUpMs)
	}
	if end.LastDownMs >= 0 {
		ev.LastDownMs = ptr(end.LastDownMs)
	}
	h.enqueue(yozhItem{end: ev})
}

func (h *WebhookNotifier) enqueue(item yozhItem) {
	// Held for the whole call, taken before the done check, as Fire does: the worker's own Add in
	// startWorker then never starts from zero while Close waits.
	h.wg.Add(1)
	defer h.wg.Done()
	select {
	case <-h.done:
		return
	default:
	}
	h.yozh.once.Do(h.startWorker)
	select {
	case h.yozh.items <- item:
	default:
		h.yozh.lost.Add(1)
	}
}

// startWorker runs on the first event, not in NewWebhookNotifier: a notifier with nothing to send
// holds no goroutine, and one dropped without Close is left to the collector.
func (h *WebhookNotifier) startWorker() {
	h.yozh.items = make(chan yozhItem, yozhQueueSize)
	if h.client.Transport == nil {
		h.client.Transport = &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     yozhIdleTimeout,
		}
	}
	h.wg.Add(1)
	go h.work()
}

// work sends the queue one event at a time. The losses since the last delivered body ride on the
// next one; an event that is not delivered is a loss of its own and gives back what it carried.
func (h *WebhookNotifier) work() {
	defer h.wg.Done()
	for {
		select {
		case <-h.done:
			return
		case item := <-h.yozh.items:
			lost := h.yozh.lost.Swap(0)
			var body any = item.end
			if item.start != nil {
				item.start.Lost = lost
				body = item.start
			} else {
				item.end.Lost = lost
			}
			if !h.send(body) {
				h.yozh.lost.Add(lost + 1)
			}
		}
	}
}

// send is post for the queue: the same request and the same log lines, and it tells whether the
// receiver took the event.
func (h *WebhookNotifier) send(body any) bool {
	payload, err := json.Marshal(body)
	if err != nil {
		errors.LogWarning(context.Background(), "webhook: marshal failed: ", err)
		return false
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		errors.LogWarning(context.Background(), "webhook: request build failed: ", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		errors.LogInfo(context.Background(), "webhook: POST failed: ", err)
		return false
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		errors.LogWarning(context.Background(), "webhook: POST returned status ", resp.StatusCode)
		return false
	}
	return true
}

// ReportsEnd implements routing.EndReporting: whether any rule asks for ends. Every dispatch asks,
// so it takes no lock: ReloadRules and RemoveRule hold r.mu while they build conditions and close
// notifiers, and the packet path must not wait for that. While a change runs, the answer is the
// one for the rules before it.
func (r *Router) ReportsEnd() bool {
	return r.reportsEnd.Load()
}

// refreshReportsEnd sets what ReportsEnd answers from the rules the router has now. It runs when a
// change of the rules is done, failed changes included: under r.mu in ReloadRules and RemoveRule,
// and at the end of Init, before the router is shared.
func (r *Router) refreshReportsEnd() {
	for _, rule := range r.rules {
		if rule.Webhook != nil && rule.Webhook.reportEnd {
			r.reportsEnd.Store(true)
			return
		}
	}
	r.reportsEnd.Store(false)
}

// ReportEnd implements routing.ConnEndReporter: the end goes through the rule that sent the start.
func (r *Route) ReportEnd(end routing.ConnEnd) {
	if r.webhook != nil && r.webhook.reportEnd {
		r.webhook.FireEnd(end)
	}
}
