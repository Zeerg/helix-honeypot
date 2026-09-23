package defense

import (
	"context"
	"errors"

	"helix-honeypot/model"
)

// StartDefenseHoneypot is intentionally unavailable. The previous active
// defense handlers streamed forever or redirected indefinitely.
func StartDefenseHoneypot(context.Context, *model.Config) error {
	return errors.New("active-defense mode is disabled")
}
