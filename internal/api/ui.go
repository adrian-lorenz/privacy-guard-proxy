package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adrian-lorenz/privacy-guard-proxy/internal/detector"
	"github.com/adrian-lorenz/privacy-guard-proxy/internal/proxy"
)

// ─── Session auth ──────────────────────────────────────────────────────────────

const adminUser = "admin"

var (
	cfgFile    string
	sessions   = map[string]struct{}{}
	sessionsMu sync.Mutex
)

// hashPassword returns hex(sha256(password)).
func hashPassword(pw string) string {
	sum := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(sum[:])
}

// uiPasswordHash returns the stored password hash, or the hash of the default
// "admin" password if none has been set yet.
func uiPasswordHash() string {
	root, _ := proxy.LoadConfigs(cfgFile)
	if root.UIPasswordHash != "" {
		return root.UIPasswordHash
	}
	return hashPassword("admin")
}

// uiMustChangePassword returns true when the admin password is still the
// factory default (no UIPasswordHash stored in config.json).
func uiMustChangePassword() bool {
	root, _ := proxy.LoadConfigs(cfgFile)
	return root.UIPasswordHash == ""
}

var allDetectors = []string{
	"EMAIL", "PHONE", "IBAN", "CREDIT_CARD", "TAX_ID",
	"SOCIAL_SECURITY", "KVNR", "VAT_ID", "PERSONAL_ID",
	"LICENSE_PLATE", "DRIVER_LICENSE", "ADDRESS", "URL_SECRET", "SECRET",
}

func newSessionToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// renderTmpl writes a named template to w. On error it sends a 500 before any
// bytes are flushed (template errors are only possible at startup if a template
// file is malformed, which would have caused a panic already).
func renderTmpl(w http.ResponseWriter, name string, data any) {
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func isAuthed(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	_, ok := sessions[c.Value]
	return ok
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	ref := r.Header.Get("Referer")
	if ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	// Non-browser clients may not send Origin/Referer.
	return true
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// ─── Login / Logout ────────────────────────────────────────────────────────────

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if isAuthed(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTmpl(w, "login", map[string]string{"Error": r.URL.Query().Get("err")})
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("username") == adminUser && hashPassword(r.FormValue("password")) == uiPasswordHash() {
		tok := newSessionToken()
		sessionsMu.Lock()
		sessions[tok] = struct{}{}
		sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isHTTPS(r),
		})
		if uiMustChangePassword() {
			http.Redirect(w, r, "/change-password", http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return
	}
	http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusFound)
}

// ─── Change password ───────────────────────────────────────────────────────────

func handleChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	renderTmpl(w, "change_password", map[string]string{"Error": r.URL.Query().Get("err")})
}

func handleChangePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	pw := r.FormValue("password")
	pw2 := r.FormValue("password2")
	if pw == "" || pw != pw2 {
		http.Redirect(w, r, "/change-password?err=Passwords+do+not+match", http.StatusFound)
		return
	}
	if len(pw) < 8 {
		http.Redirect(w, r, "/change-password?err=At+least+8+characters+required", http.StatusFound)
		return
	}
	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		http.Redirect(w, r, "/change-password?err=Configuration+error", http.StatusFound)
		return
	}
	root.UIPasswordHash = hashPassword(pw)
	if err := saveConfig(root); err != nil {
		http.Redirect(w, r, "/change-password?err=Save+error", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ─── Config page ──────────────────────────────────────────────────────────────

func handleUI(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if uiMustChangePassword() {
		http.Redirect(w, r, "/change-password", http.StatusFound)
		return
	}
	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		http.Error(w, "config error: "+err.Error(), 500)
		return
	}
	renderTmpl(w, "config", buildUIData(root))
}

func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()

	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		_, _ = fmt.Fprintf(w, `<div class="alert alert-danger py-2 mb-0">Fehler: %s</div>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// api_port
	if v := r.FormValue("api_port"); v != "" {
		if p, e := strconv.Atoi(v); e == nil {
			root.APIPort = p
		}
	} else {
		root.APIPort = 0
	}

	// default detectors
	var defDets []string
	for _, d := range allDetectors {
		if r.FormValue("default_det_"+d) == "on" {
			defDets = append(defDets, d)
		}
	}
	root.DefaultDetectors = defDets

	// default whitelist
	raw := r.FormValue("default_whitelist")
	var defWL []string
	for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if t := strings.TrimSpace(s); t != "" {
			defWL = append(defWL, t)
		}
	}
	root.DefaultWhitelist = defWL

	// cors origins
	var corsOrigins []string
	for _, s := range strings.FieldsFunc(r.FormValue("cors_origins"), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if t := strings.TrimSpace(s); t != "" {
			corsOrigins = append(corsOrigins, t)
		}
	}
	root.CORSOrigins = corsOrigins

	// per-proxy fields
	for i := range root.Proxies {
		idx := strconv.Itoa(i)
		if v := r.FormValue("port_" + idx); v != "" {
			if p, e := strconv.Atoi(v); e == nil {
				root.Proxies[i].Port = p
			}
		}
		if v := r.FormValue("upstream_" + idx); v != "" {
			root.Proxies[i].Upstream = strings.TrimRight(v, "/")
		}
		var dets []string
		for _, d := range allDetectors {
			if r.FormValue("det_"+d+"_"+idx) == "on" {
				dets = append(dets, d)
			}
		}
		root.Proxies[i].PrivacyGuard.Detectors = dets
		rawWL := r.FormValue("whitelist_" + idx)
		var wl []string
		for _, s := range strings.FieldsFunc(rawWL, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			if t := strings.TrimSpace(s); t != "" {
				wl = append(wl, t)
			}
		}
		root.Proxies[i].PrivacyGuard.Whitelist = wl
		root.Proxies[i].PrivacyGuard.DryRun = r.FormValue("dry_run_"+idx) == "on"
	}

	if err := saveConfig(root); err != nil {
		_, _ = fmt.Fprintf(w, `<div class="alert alert-danger py-2 mb-0">Save error: %s</div>`, template.HTMLEscapeString(err.Error()))
		return
	}
	applyRuntimeConfig(root)
	_, _ = fmt.Fprint(w, `<div class="alert alert-success py-2 mb-0">Saved — settings active immediately.</div>`)
}

func handleAddProxy(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	root.Proxies = append(root.Proxies, proxy.DefaultConfig())
	if err := saveConfig(root); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	idx, err := strconv.Atoi(r.URL.Query().Get("idx"))
	if err != nil {
		http.Error(w, "invalid idx", 400)
		return
	}
	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if idx < 0 || idx >= len(root.Proxies) || len(root.Proxies) <= 1 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	root.Proxies = append(root.Proxies[:idx], root.Proxies[idx+1:]...)
	if err := saveConfig(root); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// ─── API key management ────────────────────────────────────────────────────────

func generateAPIKey() (full, hash, hint string) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	full = "pgk_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(full))
	hash = hex.EncodeToString(sum[:])
	hint = full[:12] + "****"
	return
}

func newKeyID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func handleAddAPIKey(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "API Key " + time.Now().Format("2006-01-02")
	}

	full, hash, hint := generateAPIKey()

	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		_, _ = fmt.Fprintf(w, `<p class="text-danger small">%s</p>`, template.HTMLEscapeString(err.Error()))
		return
	}
	root.APIKeys = append(root.APIKeys, proxy.APIKey{
		ID:      newKeyID(),
		Name:    name,
		Hash:    hash,
		Hint:    hint,
		Created: time.Now().Format("2006-01-02"),
	})
	if err := saveConfig(root); err != nil {
		_, _ = fmt.Fprintf(w, `<p class="text-danger small">%s</p>`, template.HTMLEscapeString(err.Error()))
		return
	}
	applyRuntimeConfig(root)
	_, _ = fmt.Fprint(w, renderAPIKeySection(root.APIKeys, full))
}

func handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	root, err := proxy.LoadConfigs(cfgFile)
	if err != nil {
		_, _ = fmt.Fprintf(w, `<p class="text-danger small">%s</p>`, template.HTMLEscapeString(err.Error()))
		return
	}
	filtered := root.APIKeys[:0]
	for _, k := range root.APIKeys {
		if k.ID != id {
			filtered = append(filtered, k)
		}
	}
	root.APIKeys = filtered
	if err := saveConfig(root); err != nil {
		_, _ = fmt.Fprintf(w, `<p class="text-danger small">%s</p>`, template.HTMLEscapeString(err.Error()))
		return
	}
	applyRuntimeConfig(root)
	_, _ = fmt.Fprint(w, renderAPIKeySection(root.APIKeys, ""))
}

// renderAPIKeySection returns the innerHTML of #apikey-section.
// newKey is the full plaintext key to show once (empty = no flash).
func renderAPIKeySection(keys []proxy.APIKey, newKey string) string {
	var sb strings.Builder

	// Flash: new key just created — shown once
	if newKey != "" {
		esc := template.HTMLEscapeString(newKey)
		js := template.JSEscapeString(newKey)
		_, _ = fmt.Fprintf(&sb, `
<div class="alert alert-success alert-dismissible mb-3" role="alert">
  <div class="fw-semibold mb-1"><i class="bi bi-key me-1"></i>Key erstellt — nur einmal sichtbar, jetzt kopieren!</div>
  <div class="input-group input-group-sm">
    <input type="text" class="form-control font-monospace" value="%s" readonly id="new-key-val">
    <button class="btn btn-outline-success" type="button"
      onclick="navigator.clipboard.writeText('%s');this.innerHTML='<i class=\'bi bi-check-lg\'></i> Kopiert'">
      <i class="bi bi-clipboard"></i> Kopieren
    </button>
  </div>
  <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>`, esc, js)
	}

	// Table
	if len(keys) == 0 {
		sb.WriteString(`<p class="text-secondary small mb-3"><i class="bi bi-info-circle me-1"></i>Keine Keys konfiguriert — alle API-Anfragen werden ohne Authentifizierung akzeptiert.</p>`)
	} else {
		sb.WriteString(`<table class="table table-sm table-bordered align-middle mb-3">
<thead class="table-dark"><tr>
  <th>Name</th>
  <th>Key</th>
  <th>Erstellt</th>
  <th style="width:48px"></th>
</tr></thead><tbody>`)
		for _, k := range keys {
			_, _ = fmt.Fprintf(&sb, `<tr>
  <td class="fw-medium">%s</td>
  <td><code class="text-secondary">%s</code></td>
  <td class="text-secondary small">%s</td>
  <td>
    <button class="btn btn-sm btn-outline-danger"
      hx-post="/ui/apikey/delete?id=%s"
      hx-target="#apikey-section"
      hx-swap="innerHTML"
      hx-confirm="Really delete key &quot;%s&quot;?">
      <i class="bi bi-trash"></i>
    </button>
  </td>
</tr>`,
				template.HTMLEscapeString(k.Name),
				template.HTMLEscapeString(k.Hint),
				template.HTMLEscapeString(k.Created),
				template.HTMLEscapeString(k.ID),
				template.HTMLEscapeString(k.Name))
		}
		sb.WriteString(`</tbody></table>`)
	}

	// Add form
	sb.WriteString(`
<form class="d-flex gap-2 align-items-center"
  hx-post="/ui/apikey/add"
  hx-target="#apikey-section"
  hx-swap="innerHTML">
  <input type="text" class="form-control form-control-sm" name="name"
    placeholder="Name z.B. Claude Code" required style="max-width:280px">
  <button type="submit" class="btn btn-success btn-sm text-nowrap">
    <i class="bi bi-plus-lg"></i> Neuen Key erstellen
  </button>
</form>`)

	return sb.String()
}

// ─── Test page ────────────────────────────────────────────────────────────────

func handleTestPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	renderTmpl(w, "test", testPageData{ActivePage: "/test", Detectors: allDetectors})
}

func handleUIScan(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	text := r.FormValue("text")
	if strings.TrimSpace(text) == "" {
		_, _ = fmt.Fprint(w, `<p class="text-secondary small">Kein Text eingegeben.</p>`)
		return
	}
	var dets []string
	for _, d := range allDetectors {
		if r.FormValue("det_"+d) == "on" {
			dets = append(dets, d)
		}
	}
	anonymised, findings := detector.NewScanner(dets).Scan(text)

	var sb strings.Builder
	sb.WriteString(`<p class="text-secondary small text-uppercase fw-semibold mb-1">Anonymisierter Text</p>`)
	sb.WriteString(`<pre class="bg-body-secondary rounded p-3 small text-wrap text-break mb-3">`)
	template.HTMLEscape(&sb, []byte(anonymised))
	sb.WriteString(`</pre>`)

	if len(findings) == 0 {
		sb.WriteString(`<p class="text-secondary small">Kein PII gefunden.</p>`)
	} else {
		_, _ = fmt.Fprintf(&sb, `<p class="text-secondary small text-uppercase fw-semibold mb-2">%d Treffer</p>`, len(findings))
		sb.WriteString(`<table class="table table-sm table-bordered table-hover align-middle">`)
		sb.WriteString(`<thead class="table-dark"><tr><th>Typ</th><th>Text</th><th>Placeholder</th><th>Konfidenz</th></tr></thead><tbody>`)
		for _, f := range findings {
			_, _ = fmt.Fprintf(&sb, `<tr><td><span class="badge text-bg-primary font-monospace">%s</span></td><td class="font-monospace small text-break">`,
				template.HTMLEscapeString(string(f.Type)))
			template.HTMLEscape(&sb, []byte(f.Text))
			_, _ = fmt.Fprintf(&sb, `</td><td class="font-monospace small">%s</td><td>%.0f%%</td></tr>`,
				template.HTMLEscapeString(f.Placeholder), f.Confidence*100)
		}
		sb.WriteString(`</tbody></table>`)
	}
	_, _ = fmt.Fprint(w, sb.String())
}

// ─── Logs page ────────────────────────────────────────────────────────────────

type testPageData struct {
	ActivePage string
	Detectors  []string
}

type logsPageData struct {
	ActivePage string
	Ports      []int
	ActivePort int
	InitialLog template.HTML
}

func handleLogsPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	root, _ := proxy.LoadConfigs(cfgFile)
	var ports []int
	for _, p := range root.Proxies {
		ports = append(ports, p.Port)
	}
	active := 0
	if len(ports) > 0 {
		active = ports[0]
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("port")); err == nil {
		for _, p := range ports {
			if p == v {
				active = v
				break
			}
		}
	}
	var sb strings.Builder
	if active > 0 {
		for _, line := range tailLog(proxy.LogPath(active), 150) {
			sb.WriteString(colorizeLogLine(line))
			sb.WriteByte('\n')
		}
	}
	renderTmpl(w, "logs", logsPageData{
		ActivePage: "/logs",
		Ports:      ports,
		ActivePort: active,
		InitialLog: template.HTML(sb.String()),
	})
}

func handleLogsTail(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		// HTMX polls this endpoint; a plain 401 is not swapped into the DOM.
		// Send HX-Redirect so the browser navigates to the login page instead.
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	port := r.URL.Query().Get("port")
	if port == "" {
		slog.Warn("handleLogsTail: Kein Port angegeben")
		_, _ = fmt.Fprint(w, `<span class="text-secondary">Kein Port angegeben.</span>`)
		return
	}
	logPath := proxy.LogPath(atoi(port))
	lines := tailLog(logPath, 150)
	slog.Debug("handleLogsTail", "port", port, "path", logPath, "count", len(lines))
	var sb strings.Builder
	for _, line := range lines {
		cl := colorizeLogLine(line)
		sb.WriteString(cl)
		sb.WriteByte('\n')
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, sb.String())
}

func tailLog(path string, maxLines int) []string {
	f, err := os.Open(path)
	if err != nil {
		cwd, _ := os.Getwd()
		abs, _ := filepath.Abs(path)
		return []string{fmt.Sprintf("(No log entries found for: %s. Absolute path: %s. Current directory: %s)", path, abs, cwd)}
	}
	defer func() { _ = f.Close() }()

	const chunk = 128 * 1024
	info, err := f.Stat()
	if err != nil {
		return []string{"(Fehler beim Lesen der Datei-Informationen: " + err.Error() + ")"}
	}
	if info.Size() == 0 {
		return []string{"(Log-Datei ist leer)"}
	}

	start := info.Size() - chunk
	if start < 0 {
		start = 0
	}
	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		return []string{"(Fehler beim Suchen in Datei: " + err.Error() + ")"}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return []string{"(Fehler beim Lesen der Log-Datei: " + err.Error() + ")"}
	}

	raw := strings.TrimRight(string(data), "\n")
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	if start > 0 && len(lines) > 1 {
		lines = lines[1:]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

func colorizeLogLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return "<span>&nbsp;</span>"
	}
	escaped := template.HTMLEscapeString(line)
	class := "text-body-secondary"
	// Log format: date time method path status bytes "B" pii=N [TYPES...]
	// Example: 2026-03-14 14:51:21  POST   /v1/messages                    200    299 B  pii=0
	fields := strings.Fields(line)
	for i, f := range fields {
		if code, err := strconv.Atoi(f); err == nil && code >= 200 && code < 600 {
			// Probable status code. Usually field[4] or nearby.
			if i >= 2 {
				switch {
				case code >= 500:
					class = "text-danger"
				case code >= 400:
					class = "text-warning"
				case code >= 200:
					class = "text-success"
				}
				break
			}
		}
	}
	// Highlight pii > 0 (covers "pii=1", "pii=2 [EMAIL,IBAN]", etc.)
	if idx := strings.Index(escaped, "pii="); idx >= 0 {
		val := escaped[idx+4:]
		if len(val) > 0 && val[0] != '0' {
			escaped = escaped[:idx] + `<span class="text-warning fw-bold">` + escaped[idx:] + `</span>`
		}
	}
	return fmt.Sprintf(`<span class="%s">%s</span>`, class, escaped)
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func saveConfig(root proxy.RootConfig) error {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgFile, data, 0644)
}

// ─── Template data ────────────────────────────────────────────────────────────

type detectorItem struct {
	Name    string
	Checked bool
}

type cfgEntry struct {
	Idx       int
	Type      string
	Port      int
	Upstream  string
	Detectors []detectorItem
	AllActive bool
	Whitelist string
	DryRun    bool
	CanDelete bool
}

type uiData struct {
	ActivePage       string
	APIPort          int
	CORSOrigins      string
	APIKeysSection   template.HTML
	DefaultDetectors []detectorItem
	DefaultAllActive bool
	DefaultWhitelist string
	Proxies          []cfgEntry
}

func buildUIData(root proxy.RootConfig) uiData {
	entries := make([]cfgEntry, len(root.Proxies))
	for i, c := range root.Proxies {
		activeSet := map[string]bool{}
		for _, d := range c.PrivacyGuard.Detectors {
			activeSet[d] = true
		}
		allActive := len(c.PrivacyGuard.Detectors) == 0
		items := make([]detectorItem, len(allDetectors))
		for j, d := range allDetectors {
			items[j] = detectorItem{Name: d, Checked: allActive || activeSet[d]}
		}
		entries[i] = cfgEntry{
			Idx:       i,
			Type:      c.Type,
			Port:      c.Port,
			Upstream:  c.Upstream,
			Detectors: items,
			AllActive: allActive,
			Whitelist: strings.Join(c.PrivacyGuard.Whitelist, ", "),
			DryRun:    c.PrivacyGuard.DryRun,
			CanDelete: len(root.Proxies) > 1,
		}
	}

	defSet := map[string]bool{}
	for _, d := range root.DefaultDetectors {
		defSet[d] = true
	}
	defAllActive := len(root.DefaultDetectors) == 0
	defItems := make([]detectorItem, len(allDetectors))
	for i, d := range allDetectors {
		defItems[i] = detectorItem{Name: d, Checked: defAllActive || defSet[d]}
	}

	return uiData{
		ActivePage:       "/",
		APIPort:          root.APIPort,
		CORSOrigins:      strings.Join(root.CORSOrigins, ", "),
		APIKeysSection:   template.HTML(renderAPIKeySection(root.APIKeys, "")),
		DefaultDetectors: defItems,
		DefaultAllActive: defAllActive,
		DefaultWhitelist: strings.Join(root.DefaultWhitelist, ", "),
		Proxies:          entries,
	}
}
