package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// settingsSaveBody is the POST /api/settings/save body with every section kept
// as raw JSON. That is the only way to tell a section the caller left out from
// one it sent as false, zero or empty: decoding straight into the value structs
// gives both the same zero value.
type settingsSaveBody struct {
	Appearance json.RawMessage `json:"appearance"`
	Captcha    json.RawMessage `json:"captcha"`
	Telegram   json.RawMessage `json:"telegram"`
	SSL        json.RawMessage `json:"ssl"`
	Limits     json.RawMessage `json:"limits"`
	Gigahost   json.RawMessage `json:"gigahost"`
}

// settingsSave holds the sections a request carried. A nil section was not in
// the request and is left exactly as stored.
type settingsSave struct {
	appearance *models.AppearanceSettings
	captcha    *models.CaptchaSettings
	telegram   map[string]any
	ssl        *models.SSLSettings
	limits     *models.ConnectionLimits
	gigahost   map[string]any
}

// settingsSection is one present section and the setting key it is stored under.
type settingsSection struct {
	key   string
	value any
}

// sectionPresent reports whether the request carried the section. A JSON null is
// treated as absent: it carries no values to store.
func sectionPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// decodeSection decodes one section into its type, or returns nil when the
// request did not carry it. An explicit false or zero decodes to a non-nil
// section and is written.
func decodeSection[T any](name string, raw json.RawMessage) (*T, error) {
	if !sectionPresent(raw) {
		return nil, nil
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decode %s section: %w", name, err)
	}
	return &v, nil
}

// parseSettingsSave decodes the sections the body carries. A section whose JSON
// does not fit its type is a validation error, as it was when the whole body was
// decoded into the typed request.
func parseSettingsSave(body *settingsSaveBody) (*settingsSave, error) {
	var (
		s   settingsSave
		err error
		tg  *map[string]any
		gh  *map[string]any
	)
	if s.appearance, err = decodeSection[models.AppearanceSettings]("appearance", body.Appearance); err != nil {
		return nil, err
	}
	if s.captcha, err = decodeSection[models.CaptchaSettings]("captcha", body.Captcha); err != nil {
		return nil, err
	}
	if tg, err = decodeSection[map[string]any]("telegram", body.Telegram); err != nil {
		return nil, err
	}
	if s.ssl, err = decodeSection[models.SSLSettings]("ssl", body.SSL); err != nil {
		return nil, err
	}
	if s.limits, err = decodeSection[models.ConnectionLimits]("limits", body.Limits); err != nil {
		return nil, err
	}
	if gh, err = decodeSection[map[string]any]("gigahost", body.Gigahost); err != nil {
		return nil, err
	}
	if tg != nil {
		s.telegram = *tg
	}
	if gh != nil {
		s.gigahost = *gh
	}
	return &s, nil
}

// sections lists the present sections in the order they have always been
// written.
func (s *settingsSave) sections() []settingsSection {
	var out []settingsSection
	add := func(key string, present bool, value any) {
		if present {
			out = append(out, settingsSection{key: key, value: value})
		}
	}
	add("appearance", s.appearance != nil, s.appearance)
	add("captcha", s.captcha != nil, s.captcha)
	add("telegram", s.telegram != nil, s.telegram)
	add("ssl", s.ssl != nil, s.ssl)
	add("gigahost", s.gigahost != nil, s.gigahost)
	add("limits", s.limits != nil, s.limits)
	return out
}

// persistSettings writes the present sections in one transaction. Stored
// secrets are read inside that transaction, so the value kept for an empty or
// masked field is the one stored at write time and not one read earlier. A
// failed read or write rolls every section back.
func (h *Handlers) persistSettings(ctx context.Context, s *settingsSave) error {
	return h.db.UpdateSettings(ctx, func(tx *database.SettingsTx) error {
		if s.ssl != nil {
			if err := preserveSSLOnSave(tx, s.ssl); err != nil {
				return err
			}
		}
		if s.telegram != nil {
			if err := preserveTelegramOnSave(tx, s.telegram); err != nil {
				return err
			}
		}
		if s.gigahost != nil {
			if err := preserveGigahostOnSave(tx, s.gigahost); err != nil {
				return err
			}
		}
		for _, sec := range s.sections() {
			if err := tx.Set(sec.key, sec.value); err != nil {
				return err
			}
		}
		return nil
	})
}
