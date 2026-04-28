//go:build !windows

package main

import "golang.org/x/sys/unix"

func freeDiskMB(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	return free / (1024 * 1024), nil
}
