// Package main provides a utility to clear all sessions from a running
// go-saml IDP instance.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <idp-base-url>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s http://localhost:8000\n", os.Args[0])
		os.Exit(1)
	}

	var baseURL = os.Args[1]

	var sessions, err = listSessions(baseURL)
	if err != nil {
		logger.Error("Unable to list sessions", "error", err)
		os.Exit(1)
	}

	if len(sessions) == 0 {
		logger.Info("No active sessions found")
		return
	}

	logger.Info("Found sessions to clear", "count", len(sessions))

	for _, id := range sessions {
		err = deleteSession(baseURL, id)
		if err != nil {
			logger.Error("Unable to delete session", "error", err, "id", id)
			continue
		}
		logger.Info("Deleted session", "id", id)
	}
}

func listSessions(baseURL string) ([]string, error) {
	var resp, err = http.Get(baseURL + "/sessions/")
	if err != nil {
		return nil, fmt.Errorf("requesting sessions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 299 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Sessions []string `json:"sessions"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return nil, fmt.Errorf("decoding session list: %w", err)
	}

	return body.Sessions, nil
}

func deleteSession(baseURL, id string) error {
	var sessionURL = baseURL + "/sessions/" + url.PathEscape(id)
	var req, err = http.NewRequest(http.MethodDelete, sessionURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return nil
}
