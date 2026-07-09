package main

import (
	"log"
	"os"
	"time"

	"github.com/valyala/fasthttp"
)

// Глобальные настройки, инициализируются в main.
var (
	cfg          *Config
	allowPrivate bool
	proxyAddr    string
	adminAddr    string
	configPath   string
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	proxyAddr = getenv("PROXY_ADDR", ":3128")
	adminAddr = getenv("ADMIN_ADDR", ":8081")
	configPath = getenv("PROXY_CONFIG", "config.json")

	allowPrivate = os.Getenv("PROXY_ALLOW_PRIVATE") == "1"

	var err error
	cfg, err = LoadConfig(
		configPath,
		getenv("PROXY_USER", "freeman"),
		getenv("PROXY_PASS", "ARzg8ZGZ"),
		getenv("ADMIN_USER", "admin"),
		getenv("ADMIN_PASS", "admin"),
	)
	if err != nil {
		log.Fatalf("Failed to load config %q: %v", configPath, err)
	}

	proxyHandler := func(ctx *fasthttp.RequestCtx) {
		log.Printf("%s %s %s", ctx.Method(), ctx.URI().Host(), ctx.RequestURI())
		if string(ctx.Method()) == fasthttp.MethodConnect {
			handleConnect(ctx)
			return
		}
		handleHTTP(ctx)
	}

	proxyServer := &fasthttp.Server{
		Handler:            proxyHandler,
		Name:               "fasthttp-proxy",
		ReadTimeout:        30 * time.Second, // защита от slowloris при чтении запроса
		IdleTimeout:        90 * time.Second,
		MaxConnsPerIP:      0, // без ограничения; задайте при необходимости
		MaxRequestBodySize: 64 * 1024 * 1024,
		// WriteTimeout намеренно не задан: длинные CONNECT-туннели и
		// большие скачивания не должны рваться по таймауту записи.
	}

	adminServer := &fasthttp.Server{
		Handler:      adminHandler,
		Name:         "proxy-admin",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		adminUser, _ := cfg.AdminCredentials()
		log.Printf("Starting admin panel on %s (user=%s)", adminAddr, adminUser)
		if err := adminServer.ListenAndServe(adminAddr); err != nil {
			log.Fatalf("Admin server error: %s", err)
		}
	}()

	user, _ := cfg.Credentials()
	log.Printf("Starting fasthttp proxy on %s (user=%s, allowPrivate=%v)", proxyAddr, user, allowPrivate)
	if err := proxyServer.ListenAndServe(proxyAddr); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}
