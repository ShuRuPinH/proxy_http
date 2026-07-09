package main

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"net"
	"strings"

	"github.com/valyala/fasthttp"
)

// checkAdminAuth проверяет Basic-авторизацию для админки.
func checkAdminAuth(ctx *fasthttp.RequestCtx) bool {
	auth := string(ctx.Request.Header.Peek("Authorization"))
	if auth == "" {
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return false
	}
	user, pass := cfg.AdminCredentials()
	okUser := secureEqual(creds[0], user)
	okPass := secureEqual(creds[1], pass)
	return okUser && okPass
}

func requireAdminAuth(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("WWW-Authenticate", `Basic realm="proxy-admin"`)
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetBodyString("Unauthorized")
}

func listenPort(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr[1:]
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func requestHostname(ctx *fasthttp.RequestCtx) string {
	host := string(ctx.Host())
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func isWeakAdminPassword() bool {
	_, pass := cfg.AdminCredentials()
	weak := []string{"admin", "change-me", "password", "123456"}
	for _, w := range weak {
		if secureEqual(pass, w) {
			return true
		}
	}
	return pass == ""
}

type adminPageData struct {
	AdminPort      string
	BannerHTML     template.HTML
	AlertsHTML     template.HTML
	Hostname       string
	ProxyPort      string
	ProxyUser      string
	SSRFStatusHTML template.HTML
	ConfigPath     string
	AdminUser      string
	CurlExample    string
	EnvHTTP        string
	EnvHTTPS       string
}

const adminPageTmpl = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proxy Admin</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #0b1220; color: #e2e8f0; margin: 0;
    min-height: 100vh; line-height: 1.5;
  }
  .wrap { max-width: 920px; margin: 0 auto; padding: 32px 20px 48px; }
  h1 { margin: 0 0 6px; font-size: 26px; }
  .sub { color: #94a3b8; font-size: 14px; margin-bottom: 28px; }
  .grid { display: grid; gap: 20px; }
  @media (min-width: 720px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
  .card {
    background: #111827; border: 1px solid #1f2937; border-radius: 14px;
    padding: 22px 24px; box-shadow: 0 8px 30px rgba(0,0,0,.25);
  }
  .card h2 { margin: 0 0 14px; font-size: 16px; color: #f1f5f9; }
  .stats { display: grid; gap: 10px; }
  .stat {
    display: flex; justify-content: space-between; gap: 12px;
    padding: 10px 12px; background: #0f172a; border-radius: 8px; font-size: 13px;
  }
  .stat span { color: #94a3b8; }
  .stat strong { color: #e2e8f0; font-weight: 600; word-break: break-all; text-align: right; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em;
  }
  .badge-ok { background: #064e3b; color: #6ee7b7; }
  .badge-warn { background: #78350f; color: #fcd34d; }
  .warn-box {
    margin-bottom: 20px; padding: 14px 16px; border-radius: 10px;
    background: #451a03; border: 1px solid #92400e; color: #fde68a; font-size: 13px;
  }
  .info-box {
    margin-bottom: 20px; padding: 14px 16px; border-radius: 10px;
    background: #172554; border: 1px solid #1e40af; color: #bfdbfe; font-size: 13px;
  }
  pre {
    margin: 0; padding: 14px 16px; border-radius: 10px;
    background: #020617; border: 1px solid #1e293b;
    overflow-x: auto; font-size: 12px; line-height: 1.6; color: #cbd5e1;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .hint { color: #94a3b8; font-size: 12px; margin-top: 8px; }
  label { display: block; font-size: 13px; margin: 14px 0 6px; color: #cbd5e1; }
  input {
    width: 100%; padding: 11px 13px; border-radius: 9px;
    border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 14px;
  }
  input:focus { outline: none; border-color: #6366f1; }
  button {
    width: 100%; margin-top: 18px; padding: 12px; border: none;
    border-radius: 9px; background: #6366f1; color: white; font-size: 15px;
    font-weight: 600; cursor: pointer;
  }
  button:hover { background: #4f46e5; }
  button.secondary { background: #334155; }
  button.secondary:hover { background: #475569; }
  .msg { margin-bottom: 18px; padding: 11px 13px; border-radius: 9px; font-size: 13px; }
  .ok { background: #064e3b; color: #6ee7b7; }
  .err { background: #4c0519; color: #fda4af; }
  ol { margin: 0; padding-left: 20px; color: #cbd5e1; font-size: 13px; }
  ol li { margin: 6px 0; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>HTTP Proxy</h1>
    <div class="sub">Панель управления · порт админки {{.AdminPort}}</div>

    {{.BannerHTML}}
    {{.AlertsHTML}}

    <div class="grid grid-2">
      <div class="card">
        <h2>Статус</h2>
        <div class="stats">
          <div class="stat"><span>Прокси</span><strong>{{.Hostname}}:{{.ProxyPort}}</strong></div>
          <div class="stat"><span>Логин прокси</span><strong>{{.ProxyUser}}</strong></div>
          <div class="stat"><span>Аутентификация</span><strong>Proxy-Authorization: Basic</strong></div>
          <div class="stat"><span>SSRF-защита</span><strong>{{.SSRFStatusHTML}}</strong></div>
          <div class="stat"><span>Конфиг</span><strong>{{.ConfigPath}}</strong></div>
        </div>
      </div>

      <div class="card">
        <h2>Безопасность админки</h2>
        <div class="stats">
          <div class="stat"><span>Доступ</span><strong>Basic Auth (HTTP)</strong></div>
          <div class="stat"><span>Логин админки</span><strong>{{.AdminUser}}</strong></div>
          <div class="stat"><span>Хранение</span><strong>{{.ConfigPath}}</strong></div>
        </div>
        <p class="hint">Ограничьте доступ к порту {{.AdminPort}} файрволом. После смены кредов админки браузер запросит новый логин и пароль.</p>
      </div>
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Как подключиться к прокси</h2>
      <p class="hint" style="margin-top:0;margin-bottom:14px">Замените <code>YOUR_PASSWORD</code> на пароль прокси. Хост <code>{{.Hostname}}</code> взят из вашего текущего подключения к админке.</p>

      <p style="font-size:13px;color:#cbd5e1;margin:0 0 8px"><strong>curl</strong></p>
      <pre><code>{{.CurlExample}}</code></pre>

      <p style="font-size:13px;color:#cbd5e1;margin:18px 0 8px"><strong>Переменные окружения (Linux / macOS)</strong></p>
      <pre><code>export http_proxy="{{.EnvHTTP}}"
export https_proxy="{{.EnvHTTPS}}"</code></pre>

      <p style="font-size:13px;color:#cbd5e1;margin:18px 0 8px"><strong>Браузер / ОС</strong></p>
      <ol>
        <li>Тип прокси: <strong>HTTP</strong> (не SOCKS)</li>
        <li>Адрес: <strong>{{.Hostname}}</strong>, порт: <strong>{{.ProxyPort}}</strong></li>
        <li>Логин: <strong>{{.ProxyUser}}</strong>, пароль: ваш пароль прокси</li>
        <li>Поддерживаются HTTP и HTTPS (метод CONNECT)</li>
      </ol>
    </div>

    <div class="grid grid-2" style="margin-top:20px">
      <div class="card">
        <h2>Смена логина и пароля прокси</h2>
        <p class="hint" style="margin-top:0;margin-bottom:4px">Изменения сохраняются в <code>{{.ConfigPath}}</code> и применяются сразу, без перезапуска.</p>
        <form method="POST" action="/update-proxy">
          <label for="proxy_user">Логин прокси</label>
          <input id="proxy_user" name="proxy_user" value="{{.ProxyUser}}" autocomplete="off" required>
          <label for="proxy_pass">Новый пароль</label>
          <input id="proxy_pass" name="proxy_pass" type="password" placeholder="Введите новый пароль" autocomplete="new-password" required>
          <button type="submit">Сохранить прокси</button>
        </form>
      </div>

      <div class="card">
        <h2>Смена логина и пароля админки</h2>
        <p class="hint" style="margin-top:0;margin-bottom:4px">Креды админки тоже сохраняются в <code>{{.ConfigPath}}</code>. После сохранения потребуется повторный вход.</p>
        <form method="POST" action="/update-admin">
          <label for="admin_user">Логин админки</label>
          <input id="admin_user" name="admin_user" value="{{.AdminUser}}" autocomplete="off" required>
          <label for="admin_pass">Новый пароль</label>
          <input id="admin_pass" name="admin_pass" type="password" placeholder="Введите новый пароль" autocomplete="new-password" required>
          <button type="submit" class="secondary">Сохранить админку</button>
        </form>
      </div>
    </div>
  </div>
</body>
</html>`

var adminTmpl = template.Must(template.New("admin").Parse(adminPageTmpl))

func renderAdmin(ctx *fasthttp.RequestCtx, msg, msgClass string) {
	proxyUser, _ := cfg.Credentials()
	adminUser, _ := cfg.AdminCredentials()
	hostname := requestHostname(ctx)
	proxyPort := listenPort(proxyAddr)
	adminPort := listenPort(adminAddr)

	data := adminPageData{
		AdminPort:  adminPort,
		Hostname:   hostname,
		ProxyPort:  proxyPort,
		ProxyUser:  proxyUser,
		ConfigPath: configPath,
		AdminUser:  adminUser,
		CurlExample: "curl -x http://" + proxyUser + ":YOUR_PASSWORD@" + hostname + ":" + proxyPort + " https://example.com",
		EnvHTTP:     "http://" + proxyUser + ":YOUR_PASSWORD@" + hostname + ":" + proxyPort,
		EnvHTTPS:    "http://" + proxyUser + ":YOUR_PASSWORD@" + hostname + ":" + proxyPort,
	}

	if msg != "" {
		data.BannerHTML = template.HTML(`<div class="msg ` + template.HTMLEscapeString(msgClass) + `">` + template.HTMLEscapeString(msg) + `</div>`)
	}

	var alerts strings.Builder
	alerts.WriteString(`<div class="info-box">Страница защищена Basic Auth. Без логина и пароля админки смена настроек недоступна.</div>`)
	if isWeakAdminPassword() {
		alerts.WriteString(`<div class="warn-box"><strong>Внимание:</strong> используется слабый или стандартный пароль админки. Смените его в форме ниже и ограничьте доступ к порту `)
		alerts.WriteString(template.HTMLEscapeString(adminPort))
		alerts.WriteString(` файрволом.</div>`)
	}
	data.AlertsHTML = template.HTML(alerts.String())

	if allowPrivate {
		data.SSRFStatusHTML = template.HTML(`<span class="badge badge-warn">отключена</span>`)
	} else {
		data.SSRFStatusHTML = template.HTML(`<span class="badge badge-ok">включена</span>`)
	}

	var buf bytes.Buffer
	if err := adminTmpl.Execute(&buf, data); err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(buf.Bytes())
}

func saveConfig(ctx *fasthttp.RequestCtx, successMsg string) {
	if err := cfg.Save(); err != nil {
		renderAdmin(ctx, "Ошибка сохранения: "+err.Error(), "err")
		return
	}
	ctx.Redirect("/?ok="+successMsg, fasthttp.StatusSeeOther)
}

func adminHandler(ctx *fasthttp.RequestCtx) {
	if !checkAdminAuth(ctx) {
		requireAdminAuth(ctx)
		return
	}

	switch string(ctx.Path()) {
	case "/":
		msg := ""
		switch string(ctx.QueryArgs().Peek("ok")) {
		case "proxy":
			msg = "Учётные данные прокси обновлены"
		case "admin":
			msg = "Учётные данные админки обновлены — войдите с новым логином и паролем"
		}
		renderAdmin(ctx, msg, "ok")

	case "/update-proxy", "/update":
		if string(ctx.Method()) != fasthttp.MethodPost {
			ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			return
		}
		user := strings.TrimSpace(string(ctx.PostArgs().Peek("proxy_user")))
		pass := string(ctx.PostArgs().Peek("proxy_pass"))
		if user == "" || pass == "" {
			renderAdmin(ctx, "Логин и пароль прокси не могут быть пустыми", "err")
			return
		}
		cfg.SetCredentials(user, pass)
		saveConfig(ctx, "proxy")

	case "/update-admin":
		if string(ctx.Method()) != fasthttp.MethodPost {
			ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			return
		}
		user := strings.TrimSpace(string(ctx.PostArgs().Peek("admin_user")))
		pass := string(ctx.PostArgs().Peek("admin_pass"))
		if user == "" || pass == "" {
			renderAdmin(ctx, "Логин и пароль админки не могут быть пустыми", "err")
			return
		}
		cfg.SetAdminCredentials(user, pass)
		saveConfig(ctx, "admin")

	default:
		ctx.Error("Not Found", fasthttp.StatusNotFound)
	}
}
