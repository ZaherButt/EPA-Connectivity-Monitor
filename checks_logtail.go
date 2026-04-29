package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// tailState tracks per-check tail position. We key by check Name (not file
// path) so the state persists across log rotations: when the active file
// changes the path moves but the check's identity doesn't.
type tailState struct {
	path   string // last file we tailed (so we can detect rotation)
	offset int64  // byte offset within `path`
}

var (
	tailMu     sync.Mutex
	tailStates = map[string]*tailState{}
)

// fillLogTail tails the file at LogPath since the previous invocation,
// scanning new content for lines matching Pattern. The first run establishes a
// baseline (jumps to EOF) and reports zero matches.
//
// LogPath supports glob patterns (e.g. "...\\Trace\\Connector_*.log"). When
// the pattern contains '*' or '?' we expand it on every tick and tail the
// newest matching file by mtime — this transparently follows log rotations
// where the connector writes to a fresh GUID-suffixed file.
//
// Rotation handling: if the newest file changes between ticks, we treat the
// new file as a fresh baseline (start at its EOF) rather than re-scanning it
// in full. This avoids dumping hours of historical errors into the log on
// every rotation, which would defeat the point of incremental tailing.
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

	path, err := resolveLogPath(c.LogPath)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = "could not resolve " + c.LogPath
		return
	}

	f, err := os.Open(path)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = "could not open " + path
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
	st, seen := tailStates[c.Name]
	tailMu.Unlock()

	rotated := seen && st.path != path
	truncated := seen && !rotated && st.offset > size
	baseline := !seen || rotated || truncated

	if baseline {
		tailMu.Lock()
		tailStates[c.Name] = &tailState{path: path, offset: size}
		tailMu.Unlock()
		reason := "first sighting"
		switch {
		case rotated:
			reason = "rotated to new file " + filepath.Base(path)
		case truncated:
			reason = "file truncated"
		}
		res.Success = true
		res.Detail = fmt.Sprintf("baseline at offset=%d (%s, no scan)", size, reason)
		res.Extra = map[string]any{
			"baseline":     true,
			"offset":       size,
			"resolved":     path,
			"glob":         c.LogPath,
			"baseline_why": reason,
		}
		return
	}

	if _, err := f.Seek(st.offset, io.SeekStart); err != nil {
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
	tailStates[c.Name] = &tailState{path: path, offset: newOff}
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
		"resolved":      path,
		"glob":          c.LogPath,
	}
}

// resolveLogPath expands a glob pattern in logPath to the newest matching file
// (by mtime). If logPath contains no glob meta-characters it's returned
// unchanged. Returns a friendly error when the glob matches no files so
// log entries are debuggable from the CSV/JSON.
func resolveLogPath(logPath string) (string, error) {
	if !strings.ContainsAny(logPath, "*?[") {
		return logPath, nil
	}
	matches, err := filepath.Glob(logPath)
	if err != nil {
		return "", fmt.Errorf("glob %q: %w", logPath, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("glob %q matched no files", logPath)
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	// Multiple matches: pick the newest by mtime. Stat errors push that file
	// to the end so a hit on a deleted/locked path doesn't blank everything.
	type withTime struct {
		path string
		mod  int64
	}
	stats := make([]withTime, 0, len(matches))
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			stats = append(stats, withTime{path: m, mod: 0})
			continue
		}
		stats = append(stats, withTime{path: m, mod: fi.ModTime().UnixNano()})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].mod > stats[j].mod })
	return stats[0].path, nil
}
