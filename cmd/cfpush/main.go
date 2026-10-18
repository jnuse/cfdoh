// Command cfpush uploads pools.json (next to the executable) to its
// configured cfdoh server. All behavior lives in internal/cfpush.
package main

import (
	"fmt"
	"os"

	"github.com/jnuse/cfdoh/internal/cfpush"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "--version", "-v":
			fmt.Println(version)
			return
		case "help", "-h", "--help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "cfpush: unknown argument %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
	}
	if err := cfpush.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "cfpush:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`usage: cfpush

  (no args)   read pools.json next to the executable and upload every pool
              to its configured cfdoh server (admin/preferred report path)
  --version   print the version
`)
}
