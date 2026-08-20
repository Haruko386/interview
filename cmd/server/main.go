package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/engine"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}

	addr := flag.String("addr", ":8080", "server listen address")
	rulesPath := flag.String("rules", "rules/fingerprints.json", "fingerprint rules JSON path")
	flag.Parse()

	e, err := engine.LoadFromFile(*rulesPath)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(e).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("server listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	url := fs.String("url", "http://127.0.0.1:8080/health", "health endpoint URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 1 * time.Second,
			}).DialContext,
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unexpected status: %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
