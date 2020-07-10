// Copyright 2017-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package diskboot

import (
	"fmt"
    "os"
    "log"
	"io/ioutil"
	"path/filepath"

	"github.com/u-root/u-root/pkg/mount"
)

// ISO type contains information of a iso file, incluing its name,
// its filepath, and it's config files.
type ISO struct {
	Name      string
	Path      string
	Config    []*Config
}

// Device contains the path to a block filesystem along with its type
type Device struct {
	*mount.MountPoint
	Configs []*Config
    Isos []*ISO
}

// fstypes returns all block file system supported by the linuxboot kernel

/*
 * FindDevicesRW is identical to FindDevices, except the "RW" one
 * calls FindDevice with 0 (read write flag option)
 * In comparison, FindDevices calls FindDevice with unix.MS_RDONLY
 * which mounts the device as read only.
 */
func FindDevicesRW(devicesGlob string) (devices []*Device) {
	sysList, err := filepath.Glob(devicesGlob)
	if err != nil {
		return nil
	}
	// The Linux /sys file system is a bit, er, awkward. You can't find
	// the device special in there; just everything else.
	for _, sys := range sysList {
		blk := filepath.Join("/dev", filepath.Base(sys))

		dev, _ := FindDevice(blk, 0)
		if dev != nil && len(dev.Configs) > 0 {
			devices = append(devices, dev)
		}
	}
	return devices
}

// FindDevices searches for devices with bootable configs
func FindDevices(devicesGlob string) (devices []*Device) {
	sysList, err := filepath.Glob(devicesGlob)
	if err != nil {
		return nil
	}
	// The Linux /sys file system is a bit, er, awkward. You can't find
	// the device special in there; just everything else.
	for _, sys := range sysList {
		blk := filepath.Join("/dev", filepath.Base(sys))

		dev, _ := FindDevice(blk, mount.MS_RDONLY)
		if dev != nil && len(dev.Configs) > 0 {
			devices = append(devices, dev)
		}
	}
	return devices
}

// FindDevice attempts to construct a boot device at the given path
func FindDevice(devPath string, flags uintptr) (*Device, error) {
	mountPath, err := ioutil.TempDir("/tmp", "boot-")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp mount directory: %v", err)
	}
	mp, err := mount.TryMount(devPath, mountPath, flags)
	if err != nil {
		return nil, fmt.Errorf("failed to find a valid boot device: %v", err)
	}
	configs := FindConfigs(mountPath)
    isos := FindIsos(mountPath, flags)
    if len(configs) == 0 && len(isos) == 0 {
		return nil, fmt.Errorf("no configs anda isos on %s", devPath)
	}

	return &Device{
		MountPoint: mp,
		Configs:    configs,
        Isos:       isos,
	}, nil
}

func FindIsos(mountPath string, flags uintptr) []*ISO {
    var isos []*ISO
    
    walkfunc := func(path string, info os.FileInfo, err error) error {
        if info.IsDir() == false && filepath.Ext(path) == ".iso" {
            mountIsoPath, err := ioutil.TempDir("/tmp", "iso-")
            log.Printf(path)
            if err != nil {
                return fmt.Errorf("failed to create tmp mount directory: %v", err)
            }
            mp, err := mount.TryMount(path, mountIsoPath, flags)
            if err != nil {
                return fmt.Errorf("failed to find a valid boot device: %v", err)
                
            }
			configs := FindConfigs(mountIsoPath)
            if err := mp.Unmount(0); err != nil {			
                return fmt.Errorf("unmount(%q) = %v, want nil", mountPath, err)
            }
            if len(configs) != 0 {
                iso := &ISO{
                    Name:      info.Name(),
                    Config:   configs,
                    Path:      path,
                }
                isos = append(isos, iso)
            }
		}
		return nil
	}
    
    err := filepath.Walk(mountPath, walkfunc)
    if(err != nil){
        log.Printf("%v", err)
    }

	return isos
}
