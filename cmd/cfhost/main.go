// Command cfhost is the client entry point: it dispatches the service
// management subcommands and otherwise enters the daemon loop (the Windows
// service runtime also lands here). All behavior lives in internal/cfhost.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jnuse/cfdoh/internal/cfhost"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "install":
			exit(cfhost.Install())
		case "uninstall":
			exit(cfhost.Uninstall())
		case "start":
			exit(cfhost.Start())
		case "stop":
			exit(cfhost.Stop())
		case "run-once":
			cfg, err := cfhost.LoadConfig()
			if err != nil {
				exit(err)
			}
			exit(cfhost.RunOnce(context.Background(), cfg))
		case "status":
			fmt.Print(cfhost.Status())
			return
		case "--version", "-v":
			fmt.Println(version)
			return
		case "help", "-h", "--help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "cfhost: unknown subcommand %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
	}

	// no subcommand: daemon mode (inside the Windows service or a terminal)
	cfg, err := cfhost.LoadConfig()
	if err != nil {
		exit(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	exit(cfhost.RunLoop(ctx, cfg))
}

func exit(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "cfhost:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func usage() {
	fmt.Print(`usage: cfhost <subcommand>

  (no args)    run the daemon loop (also used by the Windows service)
  run-once     run one fetch/probe/hosts cycle and exit
  install      install the Windows service
  uninstall    remove the Windows service
  start        start the installed service
  stop         stop the installed service
  status       show the current address, last summary and next refresh
  --version    print the version
`)
}
