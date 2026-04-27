//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape processing for the given file handle.
// Required on Windows console hosts; Windows Terminal / Server 2019+ support it.
func enableVirtualTerminal(f *os.File) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

func init() {
	enableVirtualTerminal(os.Stdout)
	enableVirtualTerminal(os.Stderr)
}
