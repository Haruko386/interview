package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/internal/engine"
)

type Options struct {
	ServerURL string
	FilePath  string
	JSON      bool
	Out       io.Writer
}

func Run(opts Options) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}

	body, err := os.ReadFile(opts.FilePath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	var input []engine.Input
	if err := json.Unmarshal(body, &input); err != nil {
		return fmt.Errorf("parse input file: %w", err)
	}

	raw, err := postFingerprints(strings.TrimRight(opts.ServerURL, "/"), body)
	if err != nil {
		return err
	}

	if opts.JSON {
		_, err = opts.Out.Write(append(bytes.TrimSpace(raw), '\n'))
		return err
	}

	var results []engine.Result
	if err := json.Unmarshal(raw, &results); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}

	return renderTable(opts.Out, results)
}

func postFingerprints(serverURL string, body []byte) ([]byte, error) {
	if serverURL == "" {
		return nil, errors.New("server URL is empty")
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Post(serverURL+"/fingerprint", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("post fingerprint request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read server response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	return raw, nil
}

func renderTable(w io.Writer, results []engine.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE"); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(
			tw,
			"%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP,
			r.Port,
			r.Protocol,
			r.Product,
			r.Version,
			r.OSHint,
			r.Confidence,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}
