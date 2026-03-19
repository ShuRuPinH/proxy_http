package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	addr      = ":3128"
	proxyUser = "freeman"
	proxyPass = "ARzg8ZGZ"
)

// Проверка Proxy-Authorization: Basic ...
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
	return creds[0] == proxyUser && creds[1] == proxyPass
}

func requireAuth(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Proxy-Authenticate", `Basic realm="fasthttp-proxy"`)
	ctx.SetStatusCode(fasthttp.StatusProxyAuthRequired) // 407
	ctx.SetBodyString("Proxy Authentication Required")
}

// глобальный fasthttp.Client — HostClient/Client могут быть настроены далее
var client = &fasthttp.Client{
	Name:                          "fasthttp-proxy",
	ReadTimeout:                   20 * time.Second,
	WriteTimeout:                  20 * time.Second,
	MaxConnsPerHost:               1000,
	MaxIdleConnDuration:           90 * time.Second,
	DisableHeaderNamesNormalizing: false,
}

func handleConnect(ctx *fasthttp.RequestCtx) {
	// Basic Auth
	if !checkProxyAuth(ctx) {
		requireAuth(ctx)
		return
	}

	host := string(ctx.Request.URI().Host()) // e.g. "example.com:443"
	if host == "" {
		ctx.Error("Bad CONNECT request", fasthttp.StatusBadRequest)
		return
	}

	// Dial target
	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		ctx.Error("Unable to connect to host: "+err.Error(), fasthttp.StatusServiceUnavailable)
		return
	}

	// Enable TCP keepalive on the outgoing connection
	if tcp, ok := destConn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
		//tcp.SetDeadline(time.Now().Add(30 * time.Second))
	}

	// send 200 to client and then hijack connection
	// fasthttp: Hijack registers a handler that will be called with the underlying conn
	ctx.SetStatusCode(fasthttp.StatusOK)
	// Note: response will be flushed to the client after handler returns, and hijack handler is invoked after response goes on wire.
	ctx.Hijack(func(clientConn net.Conn) {
		defer func() {
			if clientConn != nil {
				clientConn.Close()
			}
			if destConn != nil {
				destConn.Close()
			}
		}()

		// Проверяем, не закрыты ли соединения заранее
		if clientConn == nil || destConn == nil {
			log.Println("One of connections is nil")
			return
		}
		// copy client -> dest and dest -> client concurrently
		done := make(chan struct{}, 2)
		go func() {
			defer func() { done <- struct{}{} }()
			_, err := io.Copy(destConn, clientConn)
			if err != nil {
				log.Printf("client->dest: %v", err)
			}
			if tcp, ok := destConn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			_, err := io.Copy(clientConn, destConn)
			if err != nil {
				log.Printf("dest->client: %v", err)
			}
			if tcp, ok := clientConn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
		}()

		<-done
		<-done

	})
	// note: return from handler, response (200) is written and later hijack handler will run
}

func removeProxyHeaders(req *fasthttp.Request) {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Connection")
	// optionally remove Proxy-*, Connection, Keep-Alive hop-by-hop headers
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Transfer-Encoding")
}

func handleHTTP(ctx *fasthttp.RequestCtx) {
	// Basic Auth
	if !checkProxyAuth(ctx) {
		requireAuth(ctx)
		return
	}

	// Create new request for upstream and copy incoming into it
	upReq := fasthttp.AcquireRequest()
	upResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(upReq)
	defer fasthttp.ReleaseResponse(upResp)

	// Copy incoming request to upReq (includes method, uri, headers, body)
	ctx.Request.CopyTo(upReq)

	// Remove proxy-specific headers before forwarding
	removeProxyHeaders(upReq)

	// For forward proxy, clients usually send absolute URI in RequestURI.
	// fasthttp stores full URI in upReq.URI(). We need to preserve it as is.
	// But some upstream servers expect Host header set properly:
	if len(upReq.Header.Peek("Host")) == 0 {
		if host := upReq.URI().Host(); len(host) > 0 {
			upReq.Header.SetBytesV("Host", host)
		}
	}

	// Optionally: we can rewrite RequestURI to path-only for some upstreams, but fasthttp.Client expects full RequestURI.
	// Do the request to upstream
	if err := client.Do(upReq, upResp); err != nil {
		ctx.Error("Upstream error: "+err.Error(), fasthttp.StatusBadGateway)
		return
	}

	// Copy response back to client
	// Copy status
	ctx.SetStatusCode(upResp.StatusCode())

	// Copy headers (replace any existing)
	upResp.Header.VisitAll(func(k, v []byte) {
		ctx.Response.Header.SetBytesKV(k, v)
	})

	// Write body
	body := upResp.Body()
	if len(body) > 0 {
		_, _ = ctx.Write(body)
	}
}

func main() {
	handler := func(ctx *fasthttp.RequestCtx) {
		// Simple logging
		log.Printf("%s %s %s", ctx.Method(), ctx.URI().Host(), ctx.RequestURI())

		// CONNECT for HTTPS tunneling
		if string(ctx.Method()) == "CONNECT" {
			handleConnect(ctx)
			return
		}
		// everything else: normal HTTP methods
		handleHTTP(ctx)
	}

	log.Printf("Starting fasthttp proxy on %s (user=%s)", addr, proxyUser)
	if err := fasthttp.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}
