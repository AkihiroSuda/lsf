package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/AkihiroSuda/lsf/pkg/personalities/freebsd"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/AkihiroSuda/lsf/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	if err := newApp().Execute(); err != nil {
		logrus.Fatal(err)
	}
	logrus.Debug("Exiting...")
}

func newApp() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "lsf [flags] COMMAND [ARGS...]",
		Short:        "Linux Subsystem for FreeBSD",
		Version:      strings.TrimPrefix(version.Version, "v"),
		Args:         cobra.MinimumNArgs(1),
		RunE:         mainAction,
		SilenceUsage: true,
	}
	var debugDefault bool
	if e := os.Getenv("LSF_DEBUG"); e != "" {
		var err error
		if debugDefault, err = strconv.ParseBool(e); err != nil {
			logrus.Warnf("Invalid LSF_DEBUG value %q: %v", e, err)
		}
	}
	cmd.PersistentFlags().Bool("debug", debugDefault, "debug mode [$LSF_DEBUG]")
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	return cmd
}

func mainAction(_ *cobra.Command, args []string) error {
	personality := freebsd.New()
	tracer, err := tracer.New(personality, args)
	if err != nil {
		return err
	}
	return tracer.Trace()
}
