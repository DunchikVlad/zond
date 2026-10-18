// Command zond — классификатор данных в БД (blueprint п. 1, п. 15).
// Этап 0: подкоманды version и config validate; остальные — по мере этапов.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DunchikVlad/zond/internal/config"
)

// Version и Commit заполняются при сборке (Makefile, -ldflags).
var (
	Version = "dev"
	Commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Printf("zond %s (commit %s)\n", Version, Commit)
		return 0
	case "config":
		return runConfig(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "zond: неизвестная команда %q\n", args[0])
		usage()
		return 2
	}
}

func runConfig(args []string) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "zond config: поддерживается только 'validate'")
		return 2
	}
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	dir := fs.String("dir", "configs", "каталог с конфигурационными файлами")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validate: конфигурация невалидна:\n%v\n", err)
		return 2
	}
	fmt.Printf("config validate: OK (sources=%d agents=%d labels=%d taxonomy=%s)\n",
		len(b.Connections.Sources), len(b.Detectors.Agents), len(b.Taxonomy.Labels), b.Taxonomy.Version)
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "использование: zond <version | config validate [-dir configs]>")
}
