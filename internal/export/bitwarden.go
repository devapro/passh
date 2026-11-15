package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"passh/internal/model"
)

// Bitwarden custom field types.
const (
	bwFieldText   = 0
	bwFieldHidden = 1
)

// bwLoginType is Bitwarden's item type for a login.
const bwLoginType = 1

// BitwardenTagsField is the custom field that carries an entry's tags in a
// bitwarden-json export: Bitwarden has no tags, so they become one text
// field "tags" with the tags joined by ", ". A passh custom field can't be
// named "tags", so the name never clashes.
const BitwardenTagsField = "tags"

type bwExport struct {
	Encrypted bool       `json:"encrypted"`
	Folders   []bwFolder `json:"folders"`
	Items     []bwItem   `json:"items"`
}

type bwFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bwItem struct {
	PasswordHistory *[]any    `json:"passwordHistory"`
	RevisionDate    string    `json:"revisionDate"`
	CreationDate    string    `json:"creationDate"`
	DeletedDate     *string   `json:"deletedDate"`
	ID              string    `json:"id"`
	OrganizationID  *string   `json:"organizationId"`
	FolderID        *string   `json:"folderId"`
	Type            int       `json:"type"`
	Reprompt        int       `json:"reprompt"`
	Name            string    `json:"name"`
	Notes           *string   `json:"notes"`
	Favorite        bool      `json:"favorite"`
	Fields          []bwField `json:"fields,omitempty"`
	Login           bwLogin   `json:"login"`
	CollectionIDs   *[]string `json:"collectionIds"`
}

type bwField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     int    `json:"type"`
	LinkedID *int   `json:"linkedId"`
}

type bwLogin struct {
	Fido2Credentials []any   `json:"fido2Credentials"`
	URIs             []bwURI `json:"uris,omitempty"`
	Username         *string `json:"username"`
	Password         *string `json:"password"`
	TOTP             *string `json:"totp"`
}

type bwURI struct {
	Match *int   `json:"match"`
	URI   string `json:"uri"`
}

// WriteBitwarden writes entries in Bitwarden's unencrypted JSON export
// schema ("encrypted": false), which Bitwarden and Vaultwarden import as
// "Bitwarden (json)".
//
// Mapping:
//   - every entry is a login item (type 1) named after its last path
//     segment; username, password and url go to login.username,
//     login.password and login.uris; notes to notes; empty values are null;
//   - the entry's folder becomes a Bitwarden folder named by its path
//     ("a/b"), which Bitwarden shows nested under "a"; every ancestor
//     folder is listed too, so the nesting shows. Top-level entries have no
//     folder;
//   - the first "otp" field (any case), or else the first otpauth:// value,
//     becomes login.totp;
//   - other custom fields become custom fields in order: hidden (type 1)
//     for secrets (model.IsSecret: otp and otpauth:// values), text (type 0)
//     otherwise;
//   - tags become a text field named BitwardenTagsField, since Bitwarden
//     has no tags;
//   - ids are deterministic UUIDs (SHA-256 based, version 8): an item's
//     from the entry id, a folder's from vaultID and the folder path, so
//     exporting twice gives the same ids. created_at and updated_at become
//     creationDate and revisionDate.
func WriteBitwarden(w io.Writer, vaultID string, entries []model.Entry) error {
	out := bwExport{Encrypted: false, Folders: []bwFolder{}, Items: []bwItem{}}

	folderIDs := map[string]string{}
	for _, e := range entries {
		segs := e.Path.Segments()
		for i := 1; i < len(segs); i++ {
			name := strings.Join(segs[:i], "/")
			if _, ok := folderIDs[name]; !ok {
				folderIDs[name] = derivedUUID("folder", vaultID, name)
			}
		}
	}
	names := make([]string, 0, len(folderIDs))
	for n := range folderIDs {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		out.Folders = append(out.Folders, bwFolder{ID: folderIDs[n], Name: n})
	}

	for _, e := range entries {
		item := bwItem{
			RevisionDate: bwTime(e.UpdatedAt),
			CreationDate: bwTime(e.CreatedAt),
			ID:           derivedUUID("item", e.ID),
			Type:         bwLoginType,
			Name:         e.Path.Name(),
			Notes:        nullable(e.Notes),
			Login: bwLogin{
				Fido2Credentials: []any{},
				Username:         nullable(e.Username),
				Password:         nullable(e.Password),
			},
		}
		if f := e.Path.Folder(); f != "" {
			id := folderIDs[f]
			item.FolderID = &id
		}
		if e.URL != "" {
			item.Login.URIs = []bwURI{{URI: e.URL}}
		}
		totp := totpIndex(e.Fields)
		if totp >= 0 {
			v := e.Fields[totp].Value
			item.Login.TOTP = &v
		}
		for i, f := range e.Fields {
			if i == totp {
				continue
			}
			t := bwFieldText
			if f.IsSecret() {
				t = bwFieldHidden
			}
			item.Fields = append(item.Fields, bwField{Name: f.Key, Value: f.Value, Type: t})
		}
		if len(e.Tags) > 0 {
			item.Fields = append(item.Fields, bwField{
				Name: BitwardenTagsField, Value: strings.Join(e.Tags, ", "), Type: bwFieldText,
			})
		}
		out.Items = append(out.Items, item)
	}

	var buf bytes.Buffer
	defer func() { b := buf.Bytes(); clear(b[:cap(b)]) }()
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// totpIndex returns the index of the field that becomes login.totp: the
// first "otp" field, else the first otpauth:// value, else -1.
func totpIndex(fields []model.Field) int {
	if i := slices.IndexFunc(fields, func(f model.Field) bool {
		return strings.EqualFold(f.Key, model.FieldOTP)
	}); i >= 0 {
		return i
	}
	return slices.IndexFunc(fields, func(f model.Field) bool { return model.IsOTPAuthURI(f.Value) })
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// bwTime formats t as JavaScript's toISOString does, which is what
// Bitwarden writes: "2026-11-15T12:00:00.000Z". A zero time stays zero.
func bwTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// derivedUUID returns a UUID (version 8, RFC 9562) made from the SHA-256 of
// the parts, so the same input always gives the same id.
func derivedUUID(parts ...string) string {
	h := sha256.New()
	h.Write([]byte("passh bitwarden-json id"))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	var b [16]byte
	copy(b[:], h.Sum(nil))
	b[6] = b[6]&0x0f | 0x80 // version 8
	b[8] = b[8]&0x3f | 0x80 // RFC 9562 variant
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
