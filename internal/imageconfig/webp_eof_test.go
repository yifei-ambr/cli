// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package imageconfig

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"io"
	"testing"

	webp "github.com/SeriousBug/webp-go-pure/std"
)

// A noisy alpha channel forces header probing beyond a small buffer. Generate
// the image with the dependency's encoder instead of storing a binary fixture.
func makeTransparentWebP(t testing.TB) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 128, 96))
	seed := uint32(1)
	for y := 0; y < 96; y++ {
		for x := 0; x < 128; x++ {
			seed ^= seed << 13
			seed ^= seed >> 17
			seed ^= seed << 5
			img.SetNRGBA(x, y, color.NRGBA{R: 80, G: 140, B: 200, A: uint8(seed%254 + 1)})
		}
	}
	var encoded bytes.Buffer
	if err := webp.Encode(&encoded, img, nil); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() <= 8192 {
		t.Fatalf("image too small to exercise large reads: %d", encoded.Len())
	}
	return encoded.Bytes()
}

func TestTransparentWebPFinalReadWithEOF(t *testing.T) {
	transparentWebP := makeTransparentWebP(t)
	r := &eofTrackingSource{Reader: bytes.NewReader(transparentWebP)}
	cfg, format, err := Decode(r)
	if err != nil || format != "webp" || cfg.Width != 128 || cfg.Height != 96 {
		t.Fatalf("config=%+v format=%q err=%v", cfg, format, err)
	}
	if !r.dataWithEOF {
		t.Fatal("fixture did not exercise data plus EOF")
	}
	if r.Len() != len(transparentWebP) {
		t.Fatal("source position changed")
	}
}

type eofTrackingSource struct {
	*bytes.Reader
	dataWithEOF bool
}

func (r *eofTrackingSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	if n > 0 && errors.Is(err, io.EOF) {
		r.dataWithEOF = true
	}
	return n, err
}

func TestTransparentWebPTruncated(t *testing.T) {
	transparentWebP := makeTransparentWebP(t)
	for _, end := range []int{4, 30, len(transparentWebP) / 2} {
		if _, _, err := Decode(bytes.NewReader(transparentWebP[:end])); err == nil {
			t.Fatalf("accepted truncated header/payload at %d", end)
		}
	}
}

func TestDataBeforeEOFReader(t *testing.T) {
	wrappedEOF := errors.Join(errors.New("stream ended"), io.EOF)
	for _, tc := range []struct {
		name     string
		end      error
		deferEOF bool
	}{
		{"EOF", io.EOF, true}, {"wrapped EOF", wrappedEOF, true},
		{"source failure", errors.New("storage unavailable"), false},
		{"truncation", io.ErrUnexpectedEOF, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &finalRead{err: tc.end}
			r := &dataBeforeEOFReader{Reader: source}
			b := make([]byte, 16384)
			n, err := r.Read(b)
			if n != 3 || string(b[:n]) != "end" {
				t.Fatalf("lost bytes: n=%d", n)
			}
			if tc.deferEOF {
				if err != nil {
					t.Fatalf("returned EOF before parsing data: %v", err)
				}
				n, err = r.Read(b)
				if n != 0 || !errors.Is(err, tc.end) {
					t.Fatalf("lost EOF: n=%d err=%v", n, err)
				}
				if source.calls != 1 {
					t.Fatal("read source again after EOF")
				}
			} else if !errors.Is(err, tc.end) {
				t.Fatalf("lost source error: %v", err)
			}
		})
	}
}

type finalRead struct {
	err   error
	calls int
}

func (r *finalRead) Read(p []byte) (int, error) { r.calls++; return copy(p, "end"), r.err }
