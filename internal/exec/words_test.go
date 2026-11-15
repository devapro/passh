package exec

import (
	"reflect"
	"testing"
)

func TestSplitWords(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   \t\n ", nil},
		{"vim", []string{"vim"}},
		{"  vim   -n  ", []string{"vim", "-n"}},
		{"code --wait", []string{"code", "--wait"}},
		{`'/Applications/Sublime Text.app/sl' -w`, []string{"/Applications/Sublime Text.app/sl", "-w"}},
		{`"/opt/my editor/bin/ed" --flag`, []string{"/opt/my editor/bin/ed", "--flag"}},
		{`my\ editor -x`, []string{"my editor", "-x"}},
		{`emacsclient -a '' -t`, []string{"emacsclient", "-a", "", "-t"}},
		{`a""b`, []string{"ab"}},
		{`""`, []string{""}},
		{`"it's"`, []string{"it's"}},
		{`'say "hi"'`, []string{`say "hi"`}},
		{`"a \"b\" \\ \$ \` + "`" + ` \n"`, []string{`a "b" \ $ ` + "` " + `\n`}},
		{`'no \escapes\'`, []string{`no \escapes\`}},
		{`pre'mid'"post"`, []string{"premidpost"}},
		// Nothing is expanded or interpreted.
		{`vim $HOME ~/x *.txt`, []string{"vim", "$HOME", "~/x", "*.txt"}},
		{`vim $(rm -rf ~)`, []string{"vim", "$(rm", "-rf", "~)"}},
		{"vim; rm -rf ~", []string{"vim;", "rm", "-rf", "~"}},
		{"ed|tee>x&", []string{"ed|tee>x&"}},
		{"`id`", []string{"`id`"}},
	}
	for _, tt := range tests {
		got, err := SplitWords(tt.in)
		if err != nil {
			t.Errorf("SplitWords(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("SplitWords(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitWordsErrors(t *testing.T) {
	for _, in := range []string{`'open`, `"open`, `vim "a\"`, `trailing\`} {
		if got, err := SplitWords(in); err == nil {
			t.Errorf("SplitWords(%q) = %q, want an error", in, got)
		}
	}
}
