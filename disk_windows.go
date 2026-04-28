//go:build windows

package main

import "golang.org/x/sys/windows"

func freeDiskMB(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeAvail, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeAvail, &totalBytes, &totalFree); err != nil {
		return 0, err
	}
	return freeAvail / (1024 * 1024), nil
}
