package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
)

var (
	tailMu      sync.Mutex
	tailOffsets = map[string]int64{}
)

// fillLogTail tails the file at LogPath since the previous invocation,
// scanning new content for lines matching Pattern. The first run establishes a
// baseline (jumps to EOF) and reports zero matches.
func fillLogTail(res *Result, c CheckConfig) {
	pat := c.Pattern
	if pat == "" {
		pat = `(?i)error|warn|fail|exception|disconnect`
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		res.Success = false
		res.Error = "bad pattern: " + err.Error()
		return
	}
	f, err := os.Open(c.LogPath)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = "could not open " + c.LogPath
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		return
	}
	size := fi.Size()

	tailMu.Lock()
	last, seen := tailOffsets[c.Name]
	tailMu.Unlock()

	if !seen || last > size {
		// First sighting or file rotated/truncated - establish baseline at EOF.
		tailMu.Lock()
		tailOffsets[c.Name] = size
		tailMu.Unlock()
		res.Success = true
		res.Detail = fmt.Sprintf("baseline at offset=%d (no scan)", size)
		res.Extra = map[string]any{"baseline": true, "offset": size}
		return
	}

	if _, err := f.Seek(last, io.SeekStart); err != nil {
		res.Success = false
		res.Error = err.Error()
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	matches := []string{}
	lines := 0
	for sc.Scan() {
		lines++
		line := sc.Text()
		if re.MatchString(line) {
			if len(matches) < 50 {
				matches = append(matches, line)
			}
		}
	}
	newOff, _ := f.Seek(0, io.SeekCurrent)

	tailMu.Lock()
	tailOffsets[c.Name] = newOff
	tailMu.Unlock()

	res.Success = len(matches) == 0
	res.Detail = fmt.Sprintf("scanned %d new lines, %d matches", lines, len(matches))
	if len(matches) > 0 {
		res.Error = fmt.Sprintf("%d matched lines (showing up to 50)", len(matches))
	}
	res.Extra = map[string]any{
		"lines_scanned": lines,
		"match_count":   len(matches),
		"matches":       matches,
		"offset":        newOff,
		"pattern":       pat,
	}
}
