// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package imageconfig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"io"
	"strings"
	"testing"

	webp "github.com/SeriousBug/webp-go-pure/std"
)

func tiffFixture(order binary.ByteOrder, typ uint16) []byte {
	b := make([]byte, 38)
	copy(b, "II\x2a\x00")
	if order == binary.BigEndian {
		copy(b, "MM\x00\x2a")
	}
	order.PutUint32(b[4:], 8)
	order.PutUint16(b[8:], 2)
	for i, v := range []uint32{4, 5} {
		p := b[10+i*12:]
		order.PutUint16(p, uint16(256+i))
		order.PutUint16(p[2:], typ)
		order.PutUint32(p[4:], 1)
		if typ == 3 {
			order.PutUint16(p[8:], uint16(v))
		} else {
			order.PutUint32(p[8:], v)
		}
	}
	return b
}

func bmpFixture(size uint32, bits uint16, topDown bool) []byte {
	palette := 0
	if bits <= 8 {
		palette = 4 * (1 << bits)
	}
	b := make([]byte, 14+int(size)+palette)
	copy(b, "BM")
	o := binary.LittleEndian
	o.PutUint32(b[10:], uint32(len(b)))
	o.PutUint32(b[14:], size)
	o.PutUint32(b[18:], 4)
	o.PutUint32(b[22:], 5)
	if topDown {
		o.PutUint32(b[22:], 0xfffffffb)
	}
	o.PutUint16(b[26:], 1)
	o.PutUint16(b[28:], bits)
	return b
}

func webpFixture(kind string) []byte {
	n := 10
	if kind == "VP8L" {
		n = 5
	}
	b := make([]byte, 20+n+(n&1))
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-8))
	copy(b[8:], "WEBP")
	copy(b[12:], kind)
	binary.LittleEndian.PutUint32(b[16:], uint32(n))
	p := b[20:]
	switch kind {
	case "VP8 ":
		p[0] = 0x10
		copy(p[3:], "\x9d\x01\x2a")
		binary.LittleEndian.PutUint16(p[6:], 4)
		binary.LittleEndian.PutUint16(p[8:], 5)
	case "VP8L":
		p[0] = 0x2f
		binary.LittleEndian.PutUint32(p[1:], 3|(4<<14))
	case "VP8X":
		p[0] = 2 // Animated canvas dimensions are available without frame bodies.
		p[4] = 3
		p[7] = 4
	}
	return b
}

func TestMetadataDimensions(t *testing.T) {
	fixtures := map[string][]byte{
		"tiff_le_short": tiffFixture(binary.LittleEndian, 3), "tiff_be_short": tiffFixture(binary.BigEndian, 3),
		"tiff_le_long": tiffFixture(binary.LittleEndian, 4), "tiff_be_long": tiffFixture(binary.BigEndian, 4),
		"bmp_info": bmpFixture(40, 24, false), "bmp_v4": bmpFixture(108, 32, true), "bmp_v5": bmpFixture(124, 8, false),
		"webp_lossy": webpFixture("VP8 "), "webp_lossless": webpFixture("VP8L"), "webp_extended": webpFixture("VP8X"),
	}
	for name, b := range fixtures {
		t.Run(name, func(t *testing.T) {
			r := bytes.NewReader(b)
			_, _ = r.Seek(1, io.SeekStart)
			cfg, format, err := Decode(r)
			if err != nil || cfg.Width != 4 || cfg.Height != 5 || format != name[:len(format)] || format == "" {
				t.Fatalf("%+v %q %v", cfg, format, err)
			}
			if format != "tiff" && cfg.ColorModel == nil {
				t.Fatal("discarded codec color model")
			}
			if pos, _ := r.Seek(0, io.SeekCurrent); pos != 1 {
				t.Fatal("changed source position")
			}
			// Metadata must itself be complete, even when no pixels are needed.
			required := len(b)
			if format == "tiff" {
				required -= 4
				if strings.HasSuffix(name, "short") {
					required -= 2
				} // Unused inline padding is skipped by the library.
			}
			if name == "webp_lossless" {
				required--
			}
			for n := 0; n < required; n++ {
				if _, _, err := Decode(bytes.NewReader(b[:n])); err == nil {
					t.Fatalf("accepted prefix of %d bytes", n)
				}
			}
		})
	}
}

func TestRejectMalformedMetadata(t *testing.T) {
	cases := []struct {
		name   string
		b      []byte
		mutate func([]byte)
	}{
		{"tiff_count", tiffFixture(binary.LittleEndian, 4), func(b []byte) { binary.LittleEndian.PutUint32(b[14:], 0xffffffff) }},
		{"tiff_duplicate", tiffFixture(binary.LittleEndian, 4), func(b []byte) { binary.LittleEndian.PutUint16(b[22:], 256) }},
		{"tiff_zero", tiffFixture(binary.LittleEndian, 4), func(b []byte) { binary.LittleEndian.PutUint32(b[18:], 0) }},
		{"tiff_type", tiffFixture(binary.LittleEndian, 4), func(b []byte) { binary.LittleEndian.PutUint16(b[12:], 7) }},
		{"tiff_offset", tiffFixture(binary.LittleEndian, 4), func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 0) }},
		{"bmp_header", bmpFixture(40, 24, false), func(b []byte) { binary.LittleEndian.PutUint32(b[14:], 0xffffffff) }},
		{"bmp_bitdepth", bmpFixture(40, 24, false), func(b []byte) { binary.LittleEndian.PutUint16(b[28:], 3) }},
		{"bmp_negative_width", bmpFixture(40, 24, false), func(b []byte) { binary.LittleEndian.PutUint32(b[18:], 0xffffffff) }},
		{"bmp_compression", bmpFixture(40, 24, false), func(b []byte) { binary.LittleEndian.PutUint32(b[30:], 0xffffffff) }},
		{"webp_riff", webpFixture("VP8L"), func(b []byte) { copy(b[8:], "WAVE") }},
		{"webp_chunk", webpFixture("VP8L"), func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) }},
		{"webp_version", webpFixture("VP8L"), func(b []byte) { b[24] |= 0x20 }},
		{"webp_signature", webpFixture("VP8 "), func(b []byte) { b[23] = 0 }},
		{"webp_short_chunk", webpFixture("VP8X"), func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 9) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mutate(tc.b)
			if _, _, err := Decode(bytes.NewReader(tc.b)); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
}

// Fail before any oversized read; the fixture declares an enormous unrelated
// metadata payload, which must never be read or allocated.
func TestTIFFIgnoresUnrelatedPayload(t *testing.T) {
	b := tiffFixture(binary.LittleEndian, 4)
	b = append(b[:34], make([]byte, 16)...)
	binary.LittleEndian.PutUint16(b[8:], 3)
	binary.LittleEndian.PutUint16(b[34:], 34675)
	binary.LittleEndian.PutUint16(b[36:], 7)
	binary.LittleEndian.PutUint32(b[38:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[42:], 0xffffffff)
	r := &boundedMetadataReader{Reader: bytes.NewReader(b)}
	cfg, _, err := Decode(r)
	if err != nil || cfg.Width != 4 || cfg.Height != 5 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if r.calls > 32 {
		t.Fatalf("unexpected reads: %d", r.calls)
	}
}

type boundedMetadataReader struct {
	*bytes.Reader
	calls int
}

func (r *boundedMetadataReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	if len(p) > 1024 || r.calls > 70000 {
		return 0, errors.New("metadata read budget exceeded")
	}
	return r.Reader.ReadAt(p, off)
}

func FuzzMetadata(f *testing.F) {
	f.Add(makeTransparentWebP(f))
	for _, b := range [][]byte{tiffFixture(binary.LittleEndian, 4), tiffFixture(binary.BigEndian, 3), bmpFixture(40, 24, false), webpFixture("VP8 "), webpFixture("VP8L"), webpFixture("VP8X")} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 4 {
			return
		}
		magic := string(b[:4])
		if magic != "RIFF" && magic != "II\x2a\x00" && magic != "MM\x00\x2a" && string(b[:2]) != "BM" {
			return
		}
		_, _, _ = Decode(&boundedMetadataReader{Reader: bytes.NewReader(b)})
	})
}

// WebP bounds sequential header probing even when metadata precedes pixels.
func TestWebPHeaderProbeLimit(t *testing.T) {
	b := make([]byte, 2<<20)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-8))
	copy(b[8:], "WEBP")
	copy(b[12:], "JUNK")
	binary.LittleEndian.PutUint32(b[16:], uint32(len(b)-20))
	r := &countingSource{Reader: bytes.NewReader(b)}
	if _, _, err := Decode(r); err == nil {
		t.Fatal("accepted image without dimension header")
	}
	if r.total > (1<<20)+4 {
		t.Fatalf("read %d bytes", r.total)
	}
}

type countingSource struct {
	*bytes.Reader
	total int
}

func (r *countingSource) ReadAt(p []byte, off int64) (int, error) {
	n, e := r.Reader.ReadAt(p, off)
	r.total += n
	return n, e
}

func TestMetadataPreservesReadCause(t *testing.T) {
	for _, b := range [][]byte{bmpFixture(40, 24, false), webpFixture("VP8L")} {
		sentinel := errors.New("source unavailable")
		r := &offsetReader{Reader: bytes.NewReader(b), offset: 0, err: sentinel}
		_, _, err := Decode(r)
		if !errors.Is(err, sentinel) {
			t.Fatalf("lost source error: %v", err)
		}
	}
}

func TestWebPEncodedImages(t *testing.T) {
	for _, options := range []*webp.Options{nil, {Lossless: true}, {EXIF: []byte("test")}} {
		var encoded bytes.Buffer
		if err := webp.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 4, 5)), options); err != nil {
			t.Fatal(err)
		}
		cfg, format, err := Decode(bytes.NewReader(encoded.Bytes()))
		if err != nil || format != "webp" || cfg.Width != 4 || cfg.Height != 5 {
			t.Fatalf("%+v %s %v", cfg, format, err)
		}
	}
}

func TestMetadataSourceBudget(t *testing.T) {
	r := &metadataSource{ReaderAt: bytes.NewReader(make([]byte, 16)), remaining: 4, calls: 1}
	if _, err := r.ReadAt(make([]byte, 4), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAt(make([]byte, 1), 0); !errors.Is(err, errReadBudget) {
		t.Fatalf("budget not enforced: %v", err)
	}
}

func TestTIFFTruncationPreservesEOF(t *testing.T) {
	b := tiffFixture(binary.LittleEndian, 4)
	_, _, err := Decode(bytes.NewReader(b[:30]))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("truncated scalar lost EOF: %v", err)
	}
}
