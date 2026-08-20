package main

import (
	"flag"
	"fmt"
	"os"

	clientpkg "banner-fingerprint/internal/client"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "fingerprint server URL")
	filePath := flag.String("file", "data/input.json", "input JSON file path")
	jsonOut := flag.Bool("json", false, "print raw JSON response")
	flag.Parse()

	if err := clientpkg.Run(clientpkg.Options{
		ServerURL: *serverURL,
		FilePath:  *filePath,
		JSON:      *jsonOut,
		Out:       os.Stdout,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
