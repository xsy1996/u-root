// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

// strace is a simple multi-process syscall & signal tracer.
//
// Synopsis:
//     strace <command> [args...]
//
// Description:
//	trace a single process given a command name.
package main

import (
	// Don't use spf13 flags. It will not allow commands like
	// strace ls -l
	// it tries to use the -l for strace instead of leaving it alone.
	"flag"
	"log"
	"os"
	"os/exec"

	"github.com/u-root/u-root/pkg/strace"
)

var (
	cmdUsage = "Usage: strace <command> [args...]"
)

func usage() {
	log.Fatalf(cmdUsage)
}

func main() {
	flag.Parse()

	a := flag.Args()
	if len(a) < 1 {
		usage()
	}

	c := exec.Command(a[0], a[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := strace.Strace(c, os.Stdout); err != nil {
		log.Printf("strace exited: %v", err)
	}
}
