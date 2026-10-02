package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Step is one observable action of the Wallet Instance (shown in the CLI, the web UI and the
// demo console timeline).
type Step struct {
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Info   bool      `json:"info,omitempty"`
	Title  Msg       `json:"title"`
	Detail Msg       `json:"detail"`
}

type stepRecorder struct {
	mu      sync.Mutex
	current []Step
	history []Step
	console bool
}

var demoConsoleClient = &http.Client{Timeout: 500 * time.Millisecond}

func (r *stepRecorder) add(s Step) {
	s.At = time.Now()
	s.Title = Msg{Ja: Humanize(s.Title.Ja, "ja"), En: Humanize(s.Title.En, "en")}
	s.Detail = Msg{Ja: Humanize(s.Detail.Ja, "ja"), En: Humanize(s.Detail.En, "en")}
	r.mu.Lock()
	r.current = append(r.current, s)
	r.history = append(r.history, s)
	if len(r.history) > 200 {
		r.history = r.history[len(r.history)-200:]
	}
	r.mu.Unlock()
	if r.console {
		mark := "✔"
		if s.Info {
			mark = " →"
		} else if !s.OK {
			mark = "✘"
		}
		lang := cliLang()
		if d := s.Detail.In(lang); d != "" {
			fmt.Printf("%s %s: %s\n", mark, s.Title.In(lang), d)
		} else {
			fmt.Printf("%s %s\n", mark, s.Title.In(lang))
		}
	}
	// best effort: forward to the demo console timeline
	if url := os.Getenv("DEMO_CONSOLE"); url != "" {
		level := "ok"
		if s.Info {
			level = "info"
		} else if !s.OK {
			level = "error"
		}
		body, _ := json.Marshal(map[string]string{
			"source": "Wallet Instance", "level": level,
			"message": s.Title.Ja, "message_en": s.Title.En,
			"detail": s.Detail.Ja, "detail_en": s.Detail.En,
		})
		go func() {
			if resp, err := demoConsoleClient.Post(url+"/api/events", "application/json", bytes.NewReader(body)); err == nil {
				resp.Body.Close()
			}
		}()
	}
}

// begin starts collecting the steps of one operation.
func (r *stepRecorder) begin() {
	r.mu.Lock()
	r.current = nil
	r.mu.Unlock()
}

// take returns the steps collected since begin.
func (r *stepRecorder) take() []Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.current
	r.current = nil
	return out
}

func (r *stepRecorder) recent(n int) []Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	start := 0
	if len(r.history) > n {
		start = len(r.history) - n
	}
	out := make([]Step, 0, n)
	for i := len(r.history) - 1; i >= start; i-- {
		out = append(out, r.history[i])
	}
	return out
}

func (i *Instance) ok(title, detail Msg) {
	i.steps.add(Step{OK: true, Title: title, Detail: detail})
}

func (i *Instance) info(title, detail Msg) {
	i.steps.add(Step{OK: true, Info: true, Title: title, Detail: detail})
}

// fail records a failed step and returns err.
func (i *Instance) fail(title Msg, err error) error {
	i.steps.add(Step{OK: false, Title: title, Detail: S("%s", err.Error())})
	return err
}
