package main

import (
	"encoding/base64"
	"fmt"
	"html"
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
	okUser := secureEqual(creds[0], adminUser)
	okPass := secureEqual(creds[1], adminPass)
	return okUser && okPass
}

func requireAdminAuth(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("WWW-Authenticate", `Basic realm="proxy-admin"`)
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetBodyString("Unauthorized")
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
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; margin: 0;
    min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #1e293b; padding: 32px; border-radius: 16px;
    width: 100%%; max-width: 420px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
  h1 { margin: 0 0 4px; font-size: 22px; }
  .sub { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; margin: 16px 0 6px; color: #cbd5e1; }
  input { width: 100%%; padding: 11px 13px; border-radius: 9px;
    border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 14px; }
  input:focus { outline: none; border-color: #6366f1; }
  button { width: 100%%; margin-top: 24px; padding: 12px; border: none;
    border-radius: 9px; background: #6366f1; color: white; font-size: 15px;
    font-weight: 600; cursor: pointer; }
  button:hover { background: #4f46e5; }
  .msg { margin-top: 16px; padding: 11px 13px; border-radius: 9px; font-size: 13px; }
  .ok { background: #064e3b; color: #6ee7b7; }
  .err { background: #4c0519; color: #fda4af; }
</style>
</head>
<body>
  <div class="card">
    <h1>Proxy Admin</h1>
    <div class="sub">Управление учётными данными прокси</div>
    %s
    <form method="POST" action="/update">
      <label for="proxy_user">Логин прокси</label>
      <input id="proxy_user" name="proxy_user" value="%s" autocomplete="off" required>
      <label for="proxy_pass">Новый пароль</label>
      <input id="proxy_pass" name="proxy_pass" type="password" placeholder="Введите новый пароль" autocomplete="new-password" required>
      <button type="submit">Сохранить</button>
    </form>
  </div>
</body>
</html>`

func renderAdmin(ctx *fasthttp.RequestCtx, msg, msgClass string) {
	user, _ := cfg.Credentials()
	var banner string
	if msg != "" {
		banner = fmt.Sprintf(`<div class="msg %s">%s</div>`, msgClass, html.EscapeString(msg))
	}
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	fmt.Fprintf(ctx, adminPageTmpl, banner, html.EscapeString(user))
}

func adminHandler(ctx *fasthttp.RequestCtx) {
	if !checkAdminAuth(ctx) {
		requireAdminAuth(ctx)
		return
	}

	switch string(ctx.Path()) {
	case "/":
		msg := ""
		if string(ctx.QueryArgs().Peek("ok")) == "1" {
			msg = "Учётные данные обновлены"
		}
		if msg != "" {
			renderAdmin(ctx, msg, "ok")
		} else {
			renderAdmin(ctx, "", "")
		}

	case "/update":
		if string(ctx.Method()) != fasthttp.MethodPost {
			ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
			return
		}
		user := strings.TrimSpace(string(ctx.PostArgs().Peek("proxy_user")))
		pass := string(ctx.PostArgs().Peek("proxy_pass"))
		if user == "" || pass == "" {
			renderAdmin(ctx, "Логин и пароль не могут быть пустыми", "err")
			return
		}
		cfg.SetCredentials(user, pass)
		if err := cfg.Save(); err != nil {
			renderAdmin(ctx, "Ошибка сохранения: "+err.Error(), "err")
			return
		}
		ctx.Redirect("/?ok=1", fasthttp.StatusSeeOther)

	default:
		ctx.Error("Not Found", fasthttp.StatusNotFound)
	}
}
