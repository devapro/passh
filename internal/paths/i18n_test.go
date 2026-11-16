package paths

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated renders path and folder errors in Russian and
// Serbian; English stays as it was.
func TestErrorsTranslated(t *testing.T) {
	_, perr := Parse("/work")
	_, ferr := ParseFolder("a//b")
	for _, c := range []struct {
		lang i18n.Lang
		err  error
		want string
	}{
		{i18n.En, perr, "invalid path: it starts with /"},
		{i18n.Ru, perr, "недопустимый путь: начинается с /"},
		{i18n.Sr, perr, "neispravna putanja: počinje sa /"},
		{i18n.En, ferr, "invalid folder: it has an empty segment (//)"},
		{i18n.Ru, ferr, "недопустимая папка: есть пустой сегмент (//)"},
		{i18n.Sr, ferr, "neispravna fascikla: ima prazan segment (//)"},
	} {
		if got := i18n.New(c.lang).Error(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.lang, got, c.want)
		}
	}
}
