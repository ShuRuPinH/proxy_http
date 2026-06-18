package main

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

// hop-by-hop заголовки (RFC 7230 §6.1) не должны проксироваться
// ни в запросе, ни в ответе.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// headerDeleter реализуется и RequestHeader, и ResponseHeader.
type headerDeleter interface {
	Del(key string)
}

func removeHopByHopHeaders(h headerDeleter) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func isHopByHop(key []byte) bool {
	for _, k := range hopByHopHeaders {
		if strings.EqualFold(string(key), k) {
			return true
		}
	}
	return false
}

// secureEqual сравнивает строки за постоянное время, защищая от timing-атак.
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// glob fasthttp.Client для исходящих HTTP-запросов.
var client = &fasthttp.Client{
	Name:                          "fasthttp-proxy",
	ReadTimeout:                   20 * time.Second,
	WriteTimeout:                  20 * time.Second,
	MaxConnsPerHost:               1000,
	MaxIdleConnDuration:           90 * time.Second,
	DisableHeaderNamesNormalizing: false,
	StreamResponseBody:            true,
}

// checkProxyAuth проверяет заголовок Proxy-Authorization: Basic ...
func checkProxyAuth(ctx *fasthttp.RequestCtx) bool {
	auth := string(ctx.Request.Header.Peek("Proxy-Authorization"))
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
	wantUser, wantPass := cfg.Credentials()
	// Обе проверки выполняем всегда, чтобы не давать ранний выход.
	okUser := secureEqual(creds[0], wantUser)
	okPass := secureEqual(creds[1], wantPass)
	return okUser && okPass
}

func requireAuth(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Proxy-Authenticate", `Basic realm="fasthttp-proxy"`)
	ctx.SetStatusCode(fasthttp.StatusProxyAuthRequired) // 407
	ctx.SetBodyString("Proxy Authentication Required")
}

// isBlockedTarget защищает от SSRF: если private-адреса не разрешены,
// блокирует подключения к loopback/частным/link-local адресам
// (включая облачный metadata-эндпоинт 169.254.169.254).
func isBlockedTarget(hostport string) bool {
	if allowPrivate {
		return false
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Не смогли зарезолвить — считаем небезопасным.
		return true
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

// connectHost извлекает "host:port" из CONNECT-запроса с несколькими
// фолбэками, т.к. fasthttp по-разному заполняет URI для authority-form.
func connectHost(ctx *fasthttp.RequestCtx) string {
	if h := string(ctx.Request.URI().Host()); h != "" {
		return h
	}
	if h := string(ctx.Host()); h != "" {
		return h
	}
	// request-line вида "CONNECT example.com:443 HTTP/1.1"
	reqURI := strings.TrimSpace(string(ctx.RequestURI()))
	reqURI = strings.TrimPrefix(reqURI, "//")
	return reqURI
}

func handleConnect(ctx *fasthttp.RequestCtx) {
	if !checkProxyAuth(ctx) {
		requireAuth(ctx)
		return
	}

	host := connectHost(ctx)
	if host == "" {
		ctx.Error("Bad CONNECT request", fasthttp.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		// CONNECT без порта — по умолчанию 443.
		host = net.JoinHostPort(host, "443")
	}

	if isBlockedTarget(host) {
		ctx.Error("Forbidden target", fasthttp.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		ctx.Error("Unable to connect to host: "+err.Error(), fasthttp.StatusServiceUnavailable)
		return
	}

	if tcp, ok := destConn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Hijack(func(clientConn net.Conn) {
		defer clientConn.Close()
		defer destConn.Close()

		done := make(chan struct{}, 2)
		go func() {
			defer func() { done <- struct{}{} }()
			_, err := io.Copy(destConn, clientConn)
			if err != nil {
				log.Printf("client->dest: %v", err)
			}
			if tcp, ok := destConn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			_, err := io.Copy(clientConn, destConn)
			if err != nil {
				log.Printf("dest->client: %v", err)
			}
			if tcp, ok := clientConn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()

		<-done
		<-done
	})
}

// pooledRespStream отдаёт тело ответа стримингом и возвращает
// fasthttp.Response в пул только после полной отправки клиенту.
type pooledRespStream struct {
	r    io.Reader
	resp *fasthttp.Response
}

func (p *pooledRespStream) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *pooledRespStream) Close() error {
	fasthttp.ReleaseResponse(p.resp)
	return nil
}

func handleHTTP(ctx *fasthttp.RequestCtx) {
	if !checkProxyAuth(ctx) {
		requireAuth(ctx)
		return
	}

	target := string(ctx.Request.URI().Host())
	if isBlockedTarget(target) {
		ctx.Error("Forbidden target", fasthttp.StatusForbidden)
		return
	}

	upReq := fasthttp.AcquireRequest()
	ctx.Request.CopyTo(upReq)
	removeHopByHopHeaders(&upReq.Header)

	if len(upReq.Header.Peek("Host")) == 0 {
		if host := upReq.URI().Host(); len(host) > 0 {
			upReq.Header.SetBytesV("Host", host)
		}
	}

	upResp := fasthttp.AcquireResponse()
	if err := client.Do(upReq, upResp); err != nil {
		fasthttp.ReleaseRequest(upReq)
		fasthttp.ReleaseResponse(upResp)
		ctx.Error("Upstream error: "+err.Error(), fasthttp.StatusBadGateway)
		return
	}
	fasthttp.ReleaseRequest(upReq)

	// Полностью пересобираем заголовки ответа из апстрима:
	// пропускаем hop-by-hop и Content-Length (его выставит fasthttp),
	// и используем Add, чтобы сохранить дубликаты (например, Set-Cookie).
	ctx.Response.Header.Reset()
	ctx.Response.SetStatusCode(upResp.StatusCode())
	upResp.Header.VisitAll(func(k, v []byte) {
		if isHopByHop(k) || strings.EqualFold(string(k), "Content-Length") {
			return
		}
		ctx.Response.Header.AddBytesKV(k, v)
	})

	ctx.SetBodyStream(&pooledRespStream{
		r:    upResp.BodyStream(),
		resp: upResp,
	}, upResp.Header.ContentLength())
}
