package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/devapro/passh/internal/i18n"
)

// setupHelp makes cobra's own texts speak the user's language (§3.3): the
// usage text (headings, flag lines, the closing hint), the -h/--help and
// --version flags and the help command. Cobra writes these in English, so
// passh defines them itself before cobra would; the layout stays cobra's.
// It runs once the whole command tree is built: every command gets its
// help flag here.
func (a *app) setupHelp(root *cobra.Command) {
	root.SetUsageFunc(a.usage)
	if root.Version != "" {
		root.Flags().BoolP("version", "v", false, a.T("version for %s", root.DisplayName()))
		_ = root.Flags().SetAnnotation("version", cobra.FlagSetByCobraAnnotation, []string{"true"}) // the flag was just defined
	}
	root.InitDefaultHelpCmd() // so it can be translated below; Execute keeps it
	for _, c := range root.Commands() {
		if c.Name() == "help" {
			a.setupHelpCommand(c)
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("help") == nil {
			c.Flags().BoolP("help", "h", false, a.T("help for %s", c.DisplayName()))
			_ = c.Flags().SetAnnotation("help", cobra.FlagSetByCobraAnnotation, []string{"true"}) // the flag was just defined
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// setupHelpCommand translates cobra's help command. Its Run is cobra's,
// with the message translated and errors returned instead of exiting.
func (a *app) setupHelpCommand(help *cobra.Command) {
	help.Short = a.T("Help about any command")
	help.Long = a.T("Help provides help for any command in the application.\nSimply type %s help [path to command] for full details.",
		help.Root().DisplayName())
	help.Run = nil
	help.RunE = func(c *cobra.Command, args []string) error {
		cmd, _, err := c.Root().Find(args)
		if cmd == nil || err != nil {
			c.Print(a.T("Unknown help topic %#q\n", args))
			return c.Root().Usage()
		}
		cmd.InitDefaultHelpFlag()    // no-ops: setupHelp defined them,
		cmd.InitDefaultVersionFlag() // as cobra's own help command expects
		return cmd.Help()
	}
}

// usage writes c's usage text: cobra's default layout (cobra v1.10
// defaultUsageFunc), with translated headings and flag lines.
func (a *app) usage(c *cobra.Command) error {
	var b strings.Builder
	b.WriteString(a.T("Usage:"))
	if c.Runnable() {
		fmt.Fprintf(&b, "\n  %s", c.UseLine())
	}
	if c.HasAvailableSubCommands() {
		fmt.Fprintf(&b, "\n  %s [command]", c.CommandPath())
	}
	if len(c.Aliases) > 0 {
		fmt.Fprintf(&b, "\n\n%s\n  %s", a.T("Aliases:"), c.NameAndAliases())
	}
	if c.HasExample() {
		fmt.Fprintf(&b, "\n\n%s\n%s", a.T("Examples:"), c.Example)
	}
	if c.HasAvailableSubCommands() {
		list := func(sub *cobra.Command) {
			fmt.Fprintf(&b, "\n  %-*s %s", sub.NamePadding(), sub.Name(), sub.Short)
		}
		shown := func(sub *cobra.Command) bool { return sub.IsAvailableCommand() || sub.Name() == "help" }
		if len(c.Groups()) == 0 {
			fmt.Fprintf(&b, "\n\n%s", a.T("Available Commands:"))
			for _, sub := range c.Commands() {
				if shown(sub) {
					list(sub)
				}
			}
		} else {
			for _, g := range c.Groups() {
				fmt.Fprintf(&b, "\n\n%s", g.Title)
				for _, sub := range c.Commands() {
					if sub.GroupID == g.ID && shown(sub) {
						list(sub)
					}
				}
			}
			if !c.AllChildCommandsHaveGroup() {
				fmt.Fprintf(&b, "\n\n%s", a.T("Additional Commands:"))
				for _, sub := range c.Commands() {
					if sub.GroupID == "" && shown(sub) {
						list(sub)
					}
				}
			}
		}
	}
	if c.HasAvailableLocalFlags() {
		fmt.Fprintf(&b, "\n\n%s\n%s", a.T("Flags:"), strings.TrimRightFunc(a.flagUsages(c.LocalFlags()), unicode.IsSpace))
	}
	if c.HasAvailableInheritedFlags() {
		fmt.Fprintf(&b, "\n\n%s\n%s", a.T("Global Flags:"), strings.TrimRightFunc(a.flagUsages(c.InheritedFlags()), unicode.IsSpace))
	}
	if c.HasHelpSubCommands() {
		fmt.Fprintf(&b, "\n\n%s", a.T("Additional help topics:"))
		for _, sub := range c.Commands() {
			if sub.IsAdditionalHelpTopicCommand() {
				fmt.Fprintf(&b, "\n  %-*s %s", sub.CommandPathPadding(), sub.CommandPath(), sub.Short)
			}
		}
	}
	if c.HasAvailableSubCommands() {
		fmt.Fprintf(&b, "\n\n%s", a.T("Use \"%s [command] --help\" for more information about a command.", c.CommandPath()))
	}
	b.WriteString("\n")
	_, err := io.WriteString(c.OutOrStderr(), b.String())
	return err
}

// flagUsages lists the flags of fs as pflag's FlagUsages does (v1.0.9,
// without wrapping), with the default value note translated, and columns
// counted in characters rather than bytes (a translated value name may not
// be ASCII). The usage text of each flag is passh's, translated where the
// flag is defined; a `word` in back quotes names the flag's value, as in
// pflag.
func (a *app) flagUsages(fs *pflag.FlagSet) string {
	var lines []string
	maxlen := 0
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		line := "      --" + f.Name
		if f.Shorthand != "" && f.ShorthandDeprecated == "" {
			line = "  -" + f.Shorthand + ", --" + f.Name
		}
		varname, usage := pflag.UnquoteUsage(f)
		if varname != "" {
			line += " " + varname
		}
		if f.NoOptDefVal != "" {
			switch f.Value.Type() {
			case "string":
				line += fmt.Sprintf("[=\"%s\"]", f.NoOptDefVal)
			case "bool", "boolfunc":
				if f.NoOptDefVal != "true" {
					line += "[=" + f.NoOptDefVal + "]"
				}
			case "count":
				if f.NoOptDefVal != "+1" {
					line += "[=" + f.NoOptDefVal + "]"
				}
			default:
				line += "[=" + f.NoOptDefVal + "]"
			}
		}
		line += "\x00" // where the usage column starts
		maxlen = max(maxlen, utf8.RuneCountInString(line))
		line += usage
		if !defaultIsZero(f) {
			def := f.DefValue
			if f.Value.Type() == "string" {
				def = strconv.Quote(def)
			}
			line += " " + a.T("(default %s)", def)
		}
		if f.Deprecated != "" {
			line += " " + a.T("(DEPRECATED: %s)", f.Deprecated)
		}
		lines = append(lines, line)
	})
	var b strings.Builder
	for _, line := range lines {
		col, usage, _ := strings.Cut(line, "\x00")
		// pflag: the name column, padding (maxlen counts the \x00), the
		// usage with its line breaks indented to the usage column.
		fmt.Fprintln(&b, col, strings.Repeat(" ", maxlen-utf8.RuneCountInString(col)),
			strings.ReplaceAll(usage, "\n", "\n"+strings.Repeat(" ", maxlen+2)))
	}
	return b.String()
}

// defaultIsZero reports whether f's default is its type's zero value, which
// pflag doesn't print (pflag's unexported defaultIsZeroValue, by type name).
func defaultIsZero(f *pflag.Flag) bool {
	switch f.Value.Type() {
	case "bool", "boolfunc":
		return f.DefValue == "false" || f.DefValue == ""
	case "duration":
		return f.DefValue == "0" || f.DefValue == "0s"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "count", "float32", "float64":
		return f.DefValue == "0"
	case "string":
		return f.DefValue == ""
	case "ip", "ipMask", "ipNet":
		return f.DefValue == "<nil>"
	case "intSlice", "stringSlice", "stringArray":
		return f.DefValue == "[]"
	}
	switch f.DefValue {
	case "false", "<nil>", "", "0":
		return true
	}
	return false
}

// flagError makes pflag's parse errors translatable (§3.3): an unknown
// flag, a missing or invalid value, bad flag syntax. pflag v1.0.9 writes
// them in English; flagError rebuilds each message from the typed error's
// fields and uses it only if it is exactly pflag's text, so English output
// never changes, and an error it doesn't know stays as it is.
func flagError(err error) error {
	var (
		notExist *pflag.NotExistError
		required *pflag.ValueRequiredError
		invalid  *pflag.InvalidValueError
		syntax   *pflag.InvalidSyntaxError
		msg      i18n.Message
	)
	switch {
	case errors.As(err, &notExist):
		name, short := notExist.GetSpecifiedName(), notExist.GetSpecifiedShortnames()
		switch {
		case short == "":
			msg = i18n.Msg("unknown flag: --%s", name)
		case name != "":
			msg = i18n.Msg("unknown shorthand flag: %q in -%s", rune(name[0]), short)
		}
	case errors.As(err, &required):
		name, short := required.GetSpecifiedName(), required.GetSpecifiedShortnames()
		switch {
		case short == "":
			msg = i18n.Msg("flag needs an argument: --%s", name)
		case name != "":
			msg = i18n.Msg("flag needs an argument: %q in -%s", rune(name[0]), short)
		}
	case errors.As(err, &invalid):
		f := invalid.GetFlag()
		if f == nil {
			break
		}
		name := "--" + f.Name
		if f.Shorthand != "" && f.ShorthandDeprecated == "" {
			name = "-" + f.Shorthand + ", --" + f.Name
		}
		msg = i18n.Msg("invalid argument %q for %q flag: %v", invalid.GetValue(), name, errors.Unwrap(invalid))
	case errors.As(err, &syntax):
		msg = i18n.Msg("bad flag syntax: %s", syntax.GetSpecifiedFlag())
	}
	if msg.IsZero() || msg.String() != err.Error() {
		return err
	}
	return &translatedError{err: err, msg: msg}
}

// translatedError is err with a translation: Error and Unwrap are err's,
// Localize renders msg, which says the same as err in English.
type translatedError struct {
	err error
	msg i18n.Message
}

func (e *translatedError) Error() string { return e.err.Error() }
func (e *translatedError) Unwrap() error { return e.err }

// Localize implements i18n.Localizer.
func (e *translatedError) Localize(p i18n.Printer) string { return e.msg.Localize(p) }
