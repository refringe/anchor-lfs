package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/BurntSushi/toml"

	"github.com/refringe/anchor-lfs/config"
)

// usage describes the command line.
const usage = `Usage: anchor-lfs [--config <path>] [command]

Without a command, anchor-lfs starts the server.

Commands:
  check        Validate the configuration and print it with secrets redacted, or list every problem and exit 1
  healthcheck  Exit 0 if the local server's GET /ready answers 200, or 1 otherwise
  version      Print the version, commit and build date (also --version)
  help         Print this help (also -h, --help)

Options:
  --config <path>  Configuration file (default: $ANCHOR_LFS_CONFIG, then config.toml)
`

// Command names.
const (
	commandCheck       = "check"
	commandHealthcheck = "healthcheck"
	commandVersion     = "version"
	commandHelp        = "help"
)

// redacted replaces secret values in the configuration printed by the check command.
const redacted = "<redacted>"

// runCommand parses the command line and runs the command, or the server when there is none, returning the exit code.
func runCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("anchor-lfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFlag := flags.String("config", "", "")
	versionFlag := flags.Bool("version", false, "")

	command, err := parseArgs(flags, args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		command = commandHelp
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "anchor-lfs: %v\n\n%s", err, usage)
		return 2
	case *versionFlag:
		command = commandVersion
	}

	configPath := config.ResolvePath(*configFlag)
	switch command {
	case "":
		serve(configPath)
		return 0
	case commandCheck:
		return runCheck(configPath, stdout, stderr)
	case commandHealthcheck:
		return runHealthcheck(configPath, stdout, stderr)
	case commandVersion:
		_, _ = fmt.Fprintf(stdout, "anchor-lfs %s (commit %s, built %s)\n", version, commit, date)
		return 0
	case commandHelp:
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "anchor-lfs: unknown command %q\n\n%s", command, usage)
		return 2
	}
}

// parseArgs parses flags on both sides of the command and returns the command, or "" when there is none.
func parseArgs(flags *flag.FlagSet, args []string) (string, error) {
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() == 0 {
		return "", nil
	}
	command := flags.Arg(0)
	if err := flags.Parse(flags.Args()[1:]); err != nil {
		return "", err
	}
	if flags.NArg() > 0 {
		return "", fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return command, nil
}

// runCheck loads the configuration at configPath and prints it with secrets redacted, or lists its problems.
func runCheck(configPath string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(configPath)
	if invalid, ok := errors.AsType[*config.ValidationError](err); ok {
		_, _ = fmt.Fprintf(stderr, "anchor-lfs: %s is invalid:\n", configPath)
		for _, problem := range invalid.Problems {
			_, _ = fmt.Fprintf(stderr, "  - %v\n", problem)
		}
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "anchor-lfs: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "# %s is valid. Effective configuration, with secrets redacted:\n\n", configPath)
	encoder := toml.NewEncoder(stdout)
	encoder.Indent = ""
	if err := encoder.Encode(effectiveConfig(cfg)); err != nil {
		_, _ = fmt.Fprintf(stderr, "anchor-lfs: printing configuration: %v\n", err)
		return 1
	}
	return 0
}

// effectiveConfig returns a copy of cfg with defaults spelt out, unused S3 settings dropped and secrets redacted.
func effectiveConfig(cfg *config.Config) config.Config {
	out := *cfg
	accessLog := cfg.Options.AccessLogEnabled()
	out.Options.AccessLog = &accessLog
	if out.Options.SigningKey != "" {
		out.Options.SigningKey = redacted
	}

	if cfg.Storage.Backend != config.StorageS3 {
		out.Storage = config.Storage{Backend: cfg.Storage.Backend}
		return out
	}
	presignedURLs, forcePathStyle := cfg.Storage.S3PresignedURLsEnabled(), cfg.Storage.S3ForcePathStyleEnabled()
	out.Storage.S3PresignedURLs, out.Storage.S3ForcePathStyle = &presignedURLs, &forcePathStyle
	if out.Storage.S3SecretAccessKey != "" {
		out.Storage.S3SecretAccessKey = redacted
	}
	return out
}
