package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated renders the agent's errors in Russian and Serbian:
// translated text, the durations and the pid kept, and an answer read from
// the socket translated when it is a marked key.
func TestErrorsTranslated(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	if got := ru.Error(ErrNoAgent); got != "для этого хранилища агент не запущен" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(ErrKeyBlockChanged); !strings.HasPrefix(got, "blok ključa trezora nije onaj koji je otvorio `passh unlock`") {
		t.Errorf("sr: %q", got)
	}

	ar := &AlreadyRunningError{Status: Status{IdleLeft: 15 * time.Minute, MaxLeft: 2 * time.Hour}}
	if got := ar.Error(); got != "an agent is already running for this vault: it exits in 15m0s if unused, in 2h0m0s at the latest" {
		t.Errorf("en: %q", got)
	}
	if got := ru.Error(ar); got != "для этого хранилища уже запущен агент: он завершится через 15m0s, если им не пользоваться, но не позже чем через 2h0m0s" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(i18n.Errorf("agent: %w", ar)); got != "agent: za ovaj trezor je već pokrenut agent: ugasiće se za 15m0s ako se ne koristi, a najkasnije za 2h0m0s" {
		t.Errorf("sr: %q", got)
	}
	if !errors.Is(ar, ErrAlreadyRunning) {
		t.Error("AlreadyRunningError doesn't match ErrAlreadyRunning")
	}

	// A refusal read from the socket: a marked text is translated, any
	// other text is shown as it came.
	_, err := parseResponse([]byte(`{"v":1,"ok":false,"code":"bad_request","error":"malformed request"}`))
	if got := ru.Error(err); got != "агент: агент отклонил запрос: некорректный запрос" {
		t.Errorf("ru: %q", got)
	}
	if err.Error() != "agent: the agent refused the request: malformed request" {
		t.Errorf("en: %q", err)
	}
	_, err = parseResponse([]byte(`{"v":1,"ok":false,"code":"bad_request","error":"something new"}`))
	if got := sr.Error(err); got != "agent: agent je odbio zahtev: something new" {
		t.Errorf("sr: %q", got)
	}
	_, err = parseResponse([]byte(`{"v":7}`))
	if got := ru.Error(err); !strings.Contains(got, "протокол версии 7, а этот passh — версии 1") {
		t.Errorf("ru: %q", got)
	}
}
