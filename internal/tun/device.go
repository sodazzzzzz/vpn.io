package tun

import (
	"errors"
	"fmt"
	"io"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// device adapts wgtun.Device to our simpler one-packet-per-call interface.
type device struct {
	inner wgtun.Device
	name  string
	mtu   int

	// Pre-allocated single-element slices reused on every Read so we do not
	// allocate per packet. The hot path here is the data plane.
	readBufs  [][]byte
	readSizes []int
	writeBufs [][]byte
}

func openDevice(name string, mtu int) (Device, error) {
	inner, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: create %q: %w", name, err)
	}
	actualName, err := inner.Name()
	if err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("tun: read name: %w", err)
	}
	actualMTU, err := inner.MTU()
	if err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("tun: read mtu: %w", err)
	}
	return &device{
		inner:     inner,
		name:      actualName,
		mtu:       actualMTU,
		readBufs:  make([][]byte, 1),
		readSizes: make([]int, 1),
		writeBufs: make([][]byte, 1),
	}, nil
}

// Read fills p with one IP packet and returns its length.
//
// If p is smaller than the device MTU the underlying read may still
// succeed but the packet will be truncated by the kernel/driver; always
// pass a buffer of at least dev.MTU() bytes.
func (d *device) Read(p []byte) (int, error) {
	d.readBufs[0] = p
	d.readSizes[0] = 0
	n, err := d.inner.Read(d.readBufs, d.readSizes, 0)
	if err != nil {
		// Translate the wireguard/tun close signal into io.EOF so callers
		// can treat it as a normal stream termination.
		if errors.Is(err, wgtun.ErrTooManySegments) {
			return 0, err
		}
		return 0, fmt.Errorf("tun: read: %w", err)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return d.readSizes[0], nil
}

// Write sends a single IP packet to the device.
func (d *device) Write(p []byte) (int, error) {
	d.writeBufs[0] = p
	_, err := d.inner.Write(d.writeBufs, 0)
	if err != nil {
		return 0, fmt.Errorf("tun: write: %w", err)
	}
	return len(p), nil
}

func (d *device) Name() string { return d.name }
func (d *device) MTU() int     { return d.mtu }

func (d *device) Close() error {
	if err := d.inner.Close(); err != nil {
		return fmt.Errorf("tun: close: %w", err)
	}
	return nil
}
