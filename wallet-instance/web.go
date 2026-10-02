package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Web wallet UI ("serve"). Single-user demo: operations are serialised.

type webState struct {
	mu       sync.Mutex // serialises wallet operations
	offers   map[string]*OfferPreview
	requests map[string]*PresentationPrep
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var funcs = template.FuncMap{
	"join":  strings.Join,
	"chain": func(p []string) string { return strings.Join(p, " → ") },
	"time":  func(t time.Time) string { return t.Local().Format("01/02 15:04:05") },
	"statusName": func(s *StatusResult) string {
		if s == nil {
			return "?"
		}
		return StatusTypeName(s.Status)
	},
	"statusClass": func(s *StatusResult) string {
		if s == nil {
			return "warn"
		}
		if s.Status == 0 {
			return "ok"
		}
		return "ng"
	},
	"contains": slices.Contains[[]string],
	"short": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
}

var tpl = template.Must(template.Must(template.New("layout").Funcs(funcs).Parse(layoutTpl)).Parse(stepsTpl))

func init() {
	for name, body := range map[string]string{
		"home": homeTpl, "scan": scanTpl, "offer": offerTpl, "request": requestTpl,
		"result": resultTpl, "credential": credentialTpl, "activity": activityTpl,
	} {
		template.Must(tpl.New(name).Parse(body))
	}
}

type pageData struct {
	Title   string
	Inst    *Instance
	Expiry  time.Time
	Data    any
	Steps   []Step
	Error   string
	Flash   string
	Console string
	// Wallet Instance status (Status List entry referenced by the Wallet Attestation)
	WIStatus *StatusResult
}

func (i *Instance) render(w http.ResponseWriter, name string, d pageData) {
	d.Inst = i
	d.Expiry = i.AttestationExpiry()
	d.Console = getenv("DEMO_CONSOLE", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body strings.Builder
	if err := tpl.ExecuteTemplate(&body, name, d); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := tpl.ExecuteTemplate(w, "layout", struct {
		pageData
		Body template.HTML
	}{d, template.HTML(body.String())}); err != nil {
		log.Println(err)
	}
}

func (i *Instance) serve(port string) error {
	installAttestationTransport(i)
	st := &webState{offers: map[string]*OfferPreview{}, requests: map[string]*PresentationPrep{}}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		creds, err := i.Credentials(true)
		d := pageData{Title: "ウォレット", Data: creds, Flash: r.URL.Query().Get("flash")}
		d.WIStatus, _ = i.AttestationStatus()
		if err != nil {
			d.Error = err.Error()
		}
		i.render(w, "home", d)
	})

	mux.HandleFunc("GET /scan", func(w http.ResponseWriter, r *http.Request) {
		i.render(w, "scan", pageData{Title: "読み取り"})
	})

	// Dispatch a pasted / deep-linked URI by scheme
	mux.HandleFunc("GET /open", func(w http.ResponseWriter, r *http.Request) {
		uri := strings.TrimSpace(r.URL.Query().Get("uri"))
		switch {
		case strings.HasPrefix(uri, "openid-credential-offer:"):
			http.Redirect(w, r, "/receive?offer="+url.QueryEscape(uri), http.StatusSeeOther)
		case strings.HasPrefix(uri, "openid4vp:"):
			http.Redirect(w, r, "/present?request="+url.QueryEscape(uri), http.StatusSeeOther)
		default:
			i.render(w, "scan", pageData{Title: "読み取り", Error: "openid-credential-offer:// または openid4vp: で始まる URI を入力してください"})
		}
	})

	mux.HandleFunc("GET /receive", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		preview, err := i.PreviewOffer(r.URL.Query().Get("offer"))
		d := pageData{Title: "クレデンシャルの受け取り", Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
			i.render(w, "result", d)
			return
		}
		id := newID()
		st.offers[id] = preview
		d.Data = map[string]any{"ID": id, "Preview": preview}
		i.render(w, "offer", d)
	})

	mux.HandleFunc("POST /receive", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		preview := st.offers[r.FormValue("id")]
		delete(st.offers, r.FormValue("id"))
		if preview == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		i.steps.begin()
		saved, err := i.AcceptOffer(preview)
		d := pageData{Title: "クレデンシャルの受け取り", Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Flash = fmt.Sprintf("%s を受け取りました", preview.Display.Name)
			d.Data = map[string]any{"CredentialID": saved.Entry.Id}
		}
		i.render(w, "result", d)
	})

	mux.HandleFunc("GET /present", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		prep, err := i.PreparePresentation(r.URL.Query().Get("request"))
		d := pageData{Title: "提示リクエスト", Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
			i.render(w, "result", d)
			return
		}
		id := newID()
		st.requests[id] = prep
		d.Data = map[string]any{"ID": id, "Prep": prep}
		i.render(w, "request", d)
	})

	mux.HandleFunc("POST /present", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		prep := st.requests[r.FormValue("id")]
		delete(st.requests, r.FormValue("id"))
		if prep == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.FormValue("action") == "deny" {
			i.info("提示を拒否", "%s", prep.ClientID)
			http.Redirect(w, r, "/?flash="+url.QueryEscape("提示を拒否しました"), http.StatusSeeOther)
			return
		}
		i.steps.begin()
		redirect, err := i.SubmitPresentation(prep, r.Form["claim"])
		d := pageData{Title: "提示結果", Steps: i.steps.take(), Data: map[string]any{"Redirect": redirect}}
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Flash = fmt.Sprintf("%s に提示しました", prep.RP.CommonName)
		}
		i.render(w, "result", d)
	})

	mux.HandleFunc("GET /credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		creds, err := i.Credentials(true)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for _, c := range creds {
			if c.ID == r.PathValue("id") {
				payload, _ := json.MarshalIndent(c.Payload, "", "  ")
				i.render(w, "credential", pageData{Title: c.Display.Name, Data: map[string]any{"C": c, "Payload": string(payload)}})
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("POST /attest", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		err := i.RefreshAttestation()
		d := pageData{Title: "Wallet Attestation", Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Flash = "Wallet Attestation を取得しました"
		}
		i.render(w, "result", d)
	})

	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_ = i.ResetCredentials()
		http.Redirect(w, r, "/?flash="+url.QueryEscape("クレデンシャルを削除しました"), http.StatusSeeOther)
	})

	mux.HandleFunc("GET /activity", func(w http.ResponseWriter, r *http.Request) {
		i.render(w, "activity", pageData{Title: "アクティビティ", Steps: i.steps.recent(100)})
	})

	// Summary for the demo console
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		creds, _ := i.Credentials(false)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"wallet_instance_id": i.state.WalletInstanceID,
			"attestation_exp":    i.AttestationExpiry(),
			"credentials":        len(creds),
		})
	})

	addr := "localhost:" + port
	fmt.Printf("Web wallet UI: http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

// ---- templates ---------------------------------------------------------------------------------

const layoutTpl = `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - GakuNin Wallet</title>
<style>
 :root{--c:#155e86;--bg:#e9eef2;--fg:#1f2328;--mut:#5b6670;--ok:#1a7f37;--ng:#cf222e;--warn:#9a6700;--card:#fff}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;color:var(--fg)}
 .phone{max-width:430px;margin:0 auto;min-height:100vh;background:#f7f9fb;box-shadow:0 0 24px rgba(0,0,0,.12);display:flex;flex-direction:column}
 header{background:var(--c);color:#fff;padding:14px 16px;display:flex;align-items:center;gap:10px}
 header a{color:#fff;text-decoration:none}
 header .t{font-weight:700;font-size:17px;flex:1}
 main{padding:14px 14px 90px;flex:1}
 nav{position:sticky;bottom:0;background:#fff;border-top:1px solid #d0d7de;display:flex}
 nav a{flex:1;text-align:center;padding:10px 0 12px;color:var(--mut);text-decoration:none;font-size:12px}
 nav a b{display:block;font-size:20px;line-height:1.3}
 .card{background:var(--card);border-radius:12px;padding:14px;margin:0 0 12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 .vc{border-radius:14px;padding:16px;color:#fff;margin-bottom:12px;display:block;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.18)}
 .vc .n{font-weight:700;font-size:17px}.vc .i{opacity:.85;font-size:12px;margin-top:2px}
 .vc .h{font-size:22px;margin-top:18px;font-weight:600}
 .badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700;background:#fff}
 .badge.ok{color:var(--ok)}.badge.ng{color:var(--ng)}.badge.warn{color:var(--warn)}
 .btn{display:block;width:100%;border:0;border-radius:10px;padding:13px;font-size:15px;font-weight:600;background:var(--c);color:#fff;text-align:center;text-decoration:none;cursor:pointer;margin-top:8px}
 .btn.sec{background:#fff;color:var(--c);border:1px solid var(--c)}
 .btn.danger{background:#fff;color:var(--ng);border:1px solid var(--ng)}
 .mut{color:var(--mut);font-size:12px}
 code{font-size:11px;background:#eef1f4;border-radius:4px;padding:1px 4px;word-break:break-all}
 table{width:100%;border-collapse:collapse;font-size:14px} td,th{padding:7px 4px;border-bottom:1px solid #eef1f4;text-align:left;vertical-align:top}
 th{color:var(--mut);font-weight:500;width:40%}
 .steps{list-style:none;padding:0;margin:0}
 .steps li{padding:8px 0 8px 28px;position:relative;border-bottom:1px solid #eef1f4;font-size:14px}
 .steps li:before{position:absolute;left:4px;top:8px;font-weight:700}
 .steps li.ok:before{content:"✓";color:var(--ok)} .steps li.ng:before{content:"✗";color:var(--ng)} .steps li.info:before{content:"→";color:var(--mut)}
 .steps .d{display:block;color:var(--mut);font-size:12px;word-break:break-all}
 .flash{background:#dafbe1;color:var(--ok);border-radius:10px;padding:10px 12px;margin-bottom:12px;font-weight:600}
 .error{background:#ffebe9;color:var(--ng);border-radius:10px;padding:10px 12px;margin-bottom:12px;word-break:break-all}
 textarea{width:100%;min-height:120px;border:1px solid #d0d7de;border-radius:10px;padding:10px;font-size:13px}
 label.claim{display:flex;gap:10px;align-items:flex-start;padding:9px 2px;border-bottom:1px solid #eef1f4}
 label.claim input{width:20px;height:20px;margin-top:2px}
 label.claim .v{color:var(--mut);font-size:12px;display:block}
 .tag{display:inline-block;font-size:11px;border-radius:6px;padding:1px 6px;background:#fff4d4;color:var(--warn);margin-left:4px}
 h2{font-size:15px;margin:4px 0 10px}
</style></head><body><div class="phone">
<header><a href="/">◀</a><span class="t">{{.Title}}</span><span class="mut" style="color:#cfe3ef">GakuNin Wallet</span></header>
<main>
{{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
{{if .Error}}<div class="error">✗ {{.Error}}</div>{{end}}
{{.Body}}
</main>
<nav><a href="/"><b>▤</b>クレデンシャル</a><a href="/scan"><b>⌗</b>読み取り</a><a href="/activity"><b>≡</b>アクティビティ</a>{{if .Console}}<a href="{{.Console}}" target="_blank"><b>◎</b>デモ</a>{{end}}</nav>
</div></body></html>`

const homeTpl = `
<div class="card">
 <h2>Wallet Instance</h2>
 {{if .Inst.InstanceID}}
  <div class="mut">ID <code>{{short .Inst.InstanceID 60}}</code></div>
  <div class="mut" style="margin-top:4px">Wallet Attestation:
   {{if .Expiry.IsZero}}<b style="color:var(--ng)">なし</b>{{else}}有効期限 {{time .Expiry}}{{end}}</div>
  {{with .WIStatus}}<div class="mut" style="margin-top:4px">Wallet Instance の状態:
   <span class="badge {{statusClass .}}" style="border:1px solid #d0d7de">{{statusName .}}</span> (Status List idx {{.Idx}})</div>{{end}}
 {{else}}<div class="mut">未登録です。Wallet Provider に登録して Wallet Attestation を取得してください。</div>{{end}}
 <form method="post" action="/attest"><button class="btn sec">{{if .Inst.InstanceID}}Wallet Attestation を再取得{{else}}Wallet Provider に登録{{end}}</button></form>
</div>
{{range .Data}}
 <a class="vc" href="/credentials/{{.ID}}" style="background:{{.Display.Background}};color:{{.Display.TextColor}}">
  <div style="display:flex;justify-content:space-between;align-items:start">
   <div><div class="n">{{.Display.Name}}</div><div class="i">{{if .Display.IssuerName}}{{.Display.IssuerName}}{{else}}{{.Issuer}}{{end}}</div></div>
   <span class="badge {{statusClass .Status}}">{{statusName .Status}}</span>
  </div>
  <div class="h">{{index .Disclosures "name"}}</div>
  <div class="i">{{index .Disclosures "organization"}} {{index .Disclosures "department"}}</div>
  <div class="i" style="margin-top:6px">受領 {{time .ReceivedAt}}</div>
 </a>
{{else}}
 <div class="card mut">クレデンシャルはまだありません。学認Issuer の Credential Offer を読み取ってください。</div>
{{end}}
<a class="btn" href="/scan">Offer / 提示リクエストを読み取る</a>
{{if .Data}}<form method="post" action="/reset" onsubmit="return confirm('保存済みクレデンシャルを削除しますか?')"><button class="btn danger">クレデンシャルを全て削除</button></form>{{end}}`

const scanTpl = `
<div class="card">
 <h2>URI を貼り付け</h2>
 <p class="mut">Issuer の <code>openid-credential-offer://</code> または Verifier の <code>openid4vp:</code> を貼り付けてください。
 (Issuer / Verifier の画面の「Web Wallet で開く」ボタンからも直接開けます)</p>
 <form method="get" action="/open"><textarea name="uri" placeholder="openid-credential-offer://?credential_offer=... / openid4vp:?client_id=..."></textarea>
 <button class="btn">開く</button></form>
</div>`

const stepsTpl = `{{define "steps"}}{{if .}}<div class="card"><h2>検証ステップ</h2><ul class="steps">{{range .}}<li class="{{if .Info}}info{{else if .OK}}ok{{else}}ng{{end}}">{{.Title}}{{if .Detail}}<span class="d">{{.Detail}}</span>{{end}}</li>{{end}}</ul></div>{{end}}{{end}}`

const offerTpl = `
{{$p := index .Data "Preview"}}
<div class="vc" style="background:{{$p.Display.Background}};color:{{$p.Display.TextColor}}">
 <div class="n">{{$p.Display.Name}}</div><div class="i">{{$p.Display.IssuerName}}</div>
 <div class="i" style="margin-top:14px">発行者 {{$p.Issuer}}</div>
</div>
<div class="card"><h2>発行者</h2>
 <table><tr><th>Issuer</th><td><code>{{$p.Issuer}}</code></td></tr>
 <tr><th>信頼チェーン</th><td><span class="badge ok" style="background:#dafbe1">OpenID Federation</span><div class="mut" style="margin-top:4px">{{chain $p.IssuerChain}}</div></td></tr>
 <tr><th>種別</th><td>{{join $p.ConfigurationID ", "}}</td></tr></table>
</div>
{{template "steps" .Steps}}
<form method="post" action="/receive"><input type="hidden" name="id" value="{{index .Data "ID"}}">
 <button class="btn">受け取る</button></form>
<a class="btn sec" href="/">キャンセル</a>
<p class="mut">受け取り時に Wallet Attestation と PoP を Issuer のトークンエンドポイントへ送ります。</p>`

const requestTpl = `
{{$p := index .Data "Prep"}}
<div class="card"><h2>提示を求めている相手</h2>
 <div style="font-size:18px;font-weight:700">{{$p.RP.CommonName}}</div>
 <div class="mut">{{$p.RP.Organization}} ({{$p.RP.OrganizationIdentifier}})</div>
 <table style="margin-top:8px">
  <tr><th>client_id</th><td><code>{{$p.ClientID}}</code></td></tr>
  <tr><th>アクセス証明書</th><td><span class="badge ok" style="background:#dafbe1">ETSI TS 119 411-8</span><div class="mut">policy {{$p.RP.Policy}}<br>発行 {{$p.RP.AccessCA}}</div></td></tr>
  <tr><th>Trust List</th><td><span class="badge ok" style="background:#dafbe1">ETSI TS 119 602</span><div class="mut">{{$p.LoTE.SchemeOperator}} (seq {{$p.LoTE.SequenceNumber}})<br>署名者: {{chain $p.LoTE.FederationPath}}</div></td></tr>
 </table>
</div>
<form method="post" action="/present"><input type="hidden" name="id" value="{{index .Data "ID"}}">
<div class="card"><h2>開示する属性 ({{$p.Credential.Display.Name}})</h2>
 {{range $c := $p.ClaimOrder}}
  <label class="claim"><input type="checkbox" name="claim" value="{{$c}}" {{if contains $p.Requested $c}}checked data-required="1"{{end}}>
   <span>{{$p.Credential.Label $c}}{{if contains $p.Requested $c}}<span class="tag">要求</span>{{end}}<span class="v">{{$p.Credential.Value $c}}</span></span></label>
 {{end}}
 <div id="warn" class="error" style="display:none;margin-top:10px">Verifier が要求した属性を外しています。DCQL の要求を満たさないため Verifier に拒否される可能性があります。</div>
 <p class="mut">チェックした属性だけが選択的開示 (SD-JWT) で提示されます。Key Binding JWT で本人のウォレットからの提示であることを示します。</p>
</div>
<script>
document.querySelectorAll('input[name=claim]').forEach((el) => el.addEventListener('change', () => {
  const missing = [...document.querySelectorAll('input[data-required]')].some((x) => !x.checked)
  document.getElementById('warn').style.display = missing ? 'block' : 'none'
}))
</script>
{{template "steps" .Steps}}
<button class="btn" name="action" value="present">提示する</button>
<button class="btn sec" name="action" value="deny">拒否する</button>
</form>`

const resultTpl = `
{{template "steps" .Steps}}
{{with .Data}}{{with index . "CredentialID"}}<a class="btn" href="/credentials/{{.}}">受け取ったクレデンシャルを見る</a>{{end}}{{end}}
{{with .Data}}{{with index . "Redirect"}}<a class="btn sec" href="{{.}}" target="_blank">Verifier の結果画面を開く</a>{{end}}{{end}}
<a class="btn sec" href="/">ホームへ</a>`

const credentialTpl = `
{{$c := index .Data "C"}}
<div class="vc" style="background:{{$c.Display.Background}};color:{{$c.Display.TextColor}}">
 <div style="display:flex;justify-content:space-between"><div class="n">{{$c.Display.Name}}</div><span class="badge {{statusClass $c.Status}}">{{statusName $c.Status}}</span></div>
 <div class="i">{{$c.Display.IssuerName}}</div>
</div>
<div class="card"><h2>属性 (選択的開示が可能)</h2><table>
 {{range $k := $c.ClaimNames}}<tr><th>{{$c.Label $k}}</th><td>{{$c.Value $k}}</td></tr>{{end}}
</table></div>
<div class="card"><h2>状態 (Token Status List)</h2>
 {{with $c.Status}}<table><tr><th>状態</th><td><span class="badge {{statusClass $c.Status}}" style="border:1px solid #d0d7de">{{statusName $c.Status}}</span></td></tr>
  <tr><th>idx</th><td>{{.Idx}}</td></tr><tr><th>Status List</th><td><code>{{.URI}}</code></td></tr>
  <tr><th>Status Issuer</th><td class="mut">{{chain .ChainPath}}</td></tr></table>
 {{else}}<div class="error">{{$c.StatusErr}}</div>{{end}}
</div>
<div class="card"><h2>Issuer 署名部 (SD-JWT payload)</h2><pre style="font-size:11px;white-space:pre-wrap;word-break:break-all">{{index .Data "Payload"}}</pre></div>`

const activityTpl = `{{template "steps" .Steps}}{{if not .Steps}}<div class="card mut">まだアクティビティはありません。</div>{{end}}`
