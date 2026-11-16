package cli

import (
	"strings"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
)

// language returns the language for this invocation (§3.3 `language`). It
// is needed before cobra parses the arguments, because the help texts are
// built in it, so it finds the config file as Resolve will: --config and
// --vault from args (before a "--"), then $PASSH_CONFIG, then the default
// location. Any problem (no config file, one that doesn't load) gives
// English, and the command reports the problem later as it always does.
// The agent's child command loads no config.
func language(args []string) i18n.Lang {
	if len(args) > 0 && args[0] == agent.ChildCommand {
		return i18n.En
	}
	configFlag, vaultFlag := globalFlags(args)
	cfg, err := config.Resolve(configFlag, vaultFlag)
	if err != nil {
		return i18n.En
	}
	return cfg.Language
}

// globalFlags returns the last --config and --vault values in args, written
// as "--name value" or "--name=value", before a "--" that ends the flags.
func globalFlags(args []string) (configFlag, vaultFlag string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		for _, f := range []struct {
			name string
			dst  *string
		}{{"--config", &configFlag}, {"--vault", &vaultFlag}} {
			if v, ok := strings.CutPrefix(arg, f.name+"="); ok {
				*f.dst = v
			} else if arg == f.name && i+1 < len(args) {
				i++
				*f.dst = args[i]
			}
		}
	}
	return configFlag, vaultFlag
}
