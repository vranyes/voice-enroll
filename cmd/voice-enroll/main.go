// Command voice-enroll is the self-service enrollment portal + internal
// directory for the voice call path.
//
// Two listeners: public (browser UI + enrollment JSON API) and internal
// (ClusterIP-only GET /resolve). TLS terminates at the traefik gateway;
// in-cluster traffic is plain HTTP. Key material never leaves the internal
// listener, which has no HTTPRoute by construction.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	enroll "github.com/vranyes/voice-enroll"
)

func main() {
	cfg, err := enroll.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store, err := enroll.NewPGStore(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()

	keys, err := enroll.NewKey(cfg.DEK)
	if err != nil {
		log.Fatalf("dek: %v", err)
	}
	codec, err := enroll.NewSessionCodec(cfg.SessionSecret)
	if err != nil {
		log.Fatalf("session: %v", err)
	}
	sms := &enroll.TelnyxSender{APIKey: cfg.TelnyxKey}
	srv := enroll.NewServer(store, cfg.OIDC, codec, keys, sms, cfg.TelnyxSender, cfg.LibreChatBase, cfg.EdgeSecret, cfg.TaskmasterSecret)

	pub := &http.Server{Addr: cfg.Addr, Handler: srv.PublicMux(), ReadHeaderTimeout: 5 * time.Second}
	priv := &http.Server{Addr: cfg.InternalAddr, Handler: srv.InternalMux(), ReadHeaderTimeout: 5 * time.Second}

	go func() {
		log.Printf("public listening on %s", cfg.Addr)
		if err := pub.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("public: %v", err)
		}
	}()
	go func() {
		log.Printf("internal listening on %s", cfg.InternalAddr)
		if err := priv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("internal: %v", err)
		}
	}()

	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = pub.Shutdown(shut)
	_ = priv.Shutdown(shut)
	os.Exit(0)
}
