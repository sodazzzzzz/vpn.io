package tun

import (
	"errors"
	"fmt"
	"io"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// tunRWOffset is the headroom (in bytes) reserved before each packet on every
// wireguard/tun Read/Write. The batched wireguard API places the packet at
// buf[offset:] and uses the bytes in front of it for the driver's link-layer
// header:
//
//   - macOS utun prepends a 4-byte address-family header (Read writes it into
//     buf[offset-4:]; Write rejects offset < 4).
//   - Linux with GSO/GRO offload prepends a 10-byte virtio-net header; Write
//     fails with "invalid offset" unless offset >= 10.
//
// 16 is wireguard's own MessageTransportHeaderSize and clears every platform's
// minimum, so we use it uniformly.
const tunRWOffset = 16

// device adapts wgtun.Device to our simpler one-packet-per-call interface.
//
// wireguard/tun is a *batched* API: a single Read can return many packets and
// a single Write can carry many. On Linux with offload enabled the kernel
// hands us GSO super-packets that the library splits across our buffers — if
// we supply too few, Read fails with ErrTooManySegments under download
// traffic. We therefore read a whole batch (sized to inner.BatchSize()) into
// internal buffers and hand the packets back one per Read call, keeping the
// rest of the codebase on a plain Read(p)/Write(p) byte-stream API.
type device struct {
	inner wgtun.Device
	name  string
	mtu   int

	// Read side: a batch of buffers (each with tunRWOffset headroom), the
	// per-packet sizes, how many packets the last underlying Read produced,
	// and the index of the next packet to hand out.
	rbufs  [][]byte
	rsizes []int
	rcount int
	rnext  int

	// Write side: one packet at a time, copied behind tunRWOffset headroom so
	// the driver has room for its link-layer header.
	wbuf  []byte
	wbufs [][]byte
}

func openDevice(name string, mtu int) (Device, error) {
	if name == "" {
		name = defaultTUNName
	}
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

	batch := inner.BatchSize()
	if batch < 1 {
		batch = 1
	}
	// Each buffer holds one (possibly GSO-split) packet — always <= MTU —
	// behind tunRWOffset bytes of driver headroom, plus slack.
	bufLen := tunRWOffset + actualMTU + 64
	rbufs := make([][]byte, batch)
	for i := range rbufs {
		rbufs[i] = make([]byte, bufLen)
	}

	return &device{
		inner:  inner,
		name:   actualName,
		mtu:    actualMTU,
		rbufs:  rbufs,
		rsizes: make([]int, batch),
		wbuf:   make([]byte, bufLen),
		wbufs:  make([][]byte, 1),
	}, nil
}

// Read fills p with one IP packet and returns its length. Packets from a
// single underlying batch are handed out across successive calls.
//
// If p is smaller than the packet it is truncated to len(p); always pass a
// buffer of at least dev.MTU() bytes.
func (d *device) Read(p []byte) (int, error) {
	for d.rnext >= d.rcount {
		// Current batch drained: pull the next one.
		n, err := d.inner.Read(d.rbufs, d.rsizes, tunRWOffset)
		if err != nil {
			// Surface the wireguard/tun batching signal as-is; otherwise wrap.
			if errors.Is(err, wgtun.ErrTooManySegments) {
				return 0, err
			}
			return 0, fmt.Errorf("tun: read: %w", err)
		}
		if n == 0 {
			return 0, io.EOF
		}
		// Defensive: wireguard/tun returns at most len(bufs) packets today, but
		// clamp so a future contract change can't drive the rsizes/rbufs
		// indexing below out of range.
		if n > len(d.rbufs) {
			n = len(d.rbufs)
		}
		d.rcount = n
		d.rnext = 0
	}
	i := d.rnext
	d.rnext++
	// The packet sits at rbufs[i][tunRWOffset : tunRWOffset+size]; copy returns
	// the number of bytes actually placed into p (capped at len(p)).
	size := d.rsizes[i]
	return copy(p, d.rbufs[i][tunRWOffset:tunRWOffset+size]), nil
}

// Write sends a single IP packet to the device.
//
// A packet larger than the device MTU is dropped (reported as written) rather
// than erroring: the callers tear the tunnel down on a write error, and one
// oversized/malformed frame from a peer must not take the data plane offline.
func (d *device) Write(p []byte) (int, error) {
	if len(p) > d.mtu {
		return len(p), nil
	}
	// Place the packet at wbuf[tunRWOffset:] so the driver has its leading
	// header room (macOS AF header / Linux virtio-net header) in front of it.
	buf := d.wbuf[:tunRWOffset+len(p)]
	copy(buf[tunRWOffset:], p)
	d.wbufs[0] = buf
	if _, err := d.inner.Write(d.wbufs, tunRWOffset); err != nil {
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
