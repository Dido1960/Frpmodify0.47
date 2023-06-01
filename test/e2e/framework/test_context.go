package framework

import (
	"flag"
	"fmt"
	"os"

	"github.com/onsi/ginkgo/config"
)

type TestContextType struct {
	TOOLClientPath string
	TOOLServerPath string
	LogLevel       string
	Debug          bool
}

var TestContext TestContextType

// RegisterCommonFlags registers flags common to all e2e test suites.
// The flag set can be flag.CommandLine (if desired) or a custom
// flag set that then gets passed to viperconfig.ViperizeFlags.
//
// The other Register*Flags methods below can be used to add more
// test-specific flags. However, those settings then get added
// regardless whether the test is actually in the test suite.
func RegisterCommonFlags(flags *flag.FlagSet) {
	// Turn on EmitSpecProgress to get spec progress (especially on interrupt)
	config.GinkgoConfig.EmitSpecProgress = true

	// Randomize specs as well as suites
	config.GinkgoConfig.RandomizeAllSpecs = true

	flags.StringVar(&TestContext.TOOLClientPath, "client-path", "../../bin/client", "The tool client binary to use.")
	flags.StringVar(&TestContext.TOOLServerPath, "server-path", "../../bin/server", "The tool server binary to use.")
	flags.StringVar(&TestContext.LogLevel, "log-level", "debug", "Log level.")
	flags.BoolVar(&TestContext.Debug, "debug", false, "Enable debug mode to print detail info.")
}

func ValidateTestContext(t *TestContextType) error {
	if t.TOOLClientPath == "" || t.TOOLServerPath == "" {
		return fmt.Errorf("client and server binary path can't be empty")
	}
	if _, err := os.Stat(t.TOOLClientPath); err != nil {
		return fmt.Errorf("load client-path error: %v", err)
	}
	if _, err := os.Stat(t.TOOLServerPath); err != nil {
		return fmt.Errorf("load server-path error: %v", err)
	}
	return nil
}
