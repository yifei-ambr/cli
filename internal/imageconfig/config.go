// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

// Package imageconfig reads dimensions without decoding image pixels.
package imageconfig

import (
	"errors"
	"image"
	"io"
	"math"

	webp "github.com/SeriousBug/webp-go-pure/std"
	"github.com/bep/imagemeta"
	"github.com/jsummers/gobmp"
)

var errMetadata = errors.New("invalid or unsupported image dimensions")
var errReadBudget = errors.New("image metadata read limit exceeded")

// Decode reads dimensions without consuming r. A successful result does not
// validate the complete image; TIFF provides dimensions only, with no color model.
// Shared format dispatch, read limits, and codec IO adapters live here so callers
// can pass any supported image without duplicating that logic.
func Decode(r io.ReaderAt) (image.Config, string, error) {
	source := &metadataSource{ReaderAt: r, remaining: 2 << 20, calls: 65536}
	var magic [4]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil {
		return image.Config{}, "", err
	}
	reader := io.NewSectionReader(source, 0, math.MaxInt64)
	var cfg image.Config
	var format string
	var err error
	switch {
	case string(magic[:]) == "II\x2a\x00" || string(magic[:]) == "MM\x00\x2a":
		format = "tiff"
		cfg, err = readTIFF(reader)
	case string(magic[:2]) == "BM":
		// gobmp limits each axis to 46340 and area to less than 0x20000000.
		format = "bmp"
		cfg, err = gobmp.DecodeConfig(reader)
	case string(magic[:]) == "RIFF":
		// The codec limits sequential header probing to 1 MiB.
		format = "webp"
		cfg, err = webp.DecodeConfig(&dataBeforeEOFReader{Reader: reader})
	default:
		// Keep the standard-library readers' existing limits for other formats.
		return image.DecodeConfig(io.NewSectionReader(r, 0, math.MaxInt64))
	}
	// Some metadata libraries intentionally swallow stream errors. A failed
	// source read must not become a successful dimension result or lose its cause.
	if source.err != nil && !(format == "webp" && errors.Is(source.err, io.EOF)) {
		return image.Config{}, format, source.err
	}
	if err != nil {
		return image.Config{}, format, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return image.Config{}, format, errMetadata
	}
	return cfg, format, nil
}

// dataBeforeEOFReader lets codecs consume the final bytes before seeing EOF.
// Unlike bufio.Reader, it also handles reads larger than a buffering layer.
// Other source failures are returned immediately and retain their causes.
type dataBeforeEOFReader struct {
	io.Reader
	pendingEOF error
}

func (r *dataBeforeEOFReader) Read(p []byte) (int, error) {
	if r.pendingEOF != nil {
		return 0, r.pendingEOF
	}
	n, err := r.Reader.Read(p)
	if n > 0 && errors.Is(err, io.EOF) {
		r.pendingEOF = err
		return n, nil
	}
	return n, err
}

// metadataSource bounds cumulative IO, not offsets, so a distant TIFF IFD can
// still be read without buffering its preceding bytes. No format is parsed here.
type metadataSource struct {
	io.ReaderAt
	remaining, calls int
	err              error
}

func (r *metadataSource) ReadAt(p []byte, off int64) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) > r.remaining || r.calls == 0 {
		r.err = errReadBudget
		return 0, r.err
	}
	r.calls--
	n, err := r.ReaderAt.ReadAt(p, off)
	r.remaining -= n
	if n == len(p) {
		return n, nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	// Record EOF too: TIFF may otherwise return stale values after truncation.
	// WebP alone may legitimately reach EOF while buffering a complete header.
	r.err = err
	return n, err
}

func readTIFF(r io.ReadSeeker) (image.Config, error) {
	var values [2]int64
	var seen [2]bool
	err := imagemeta.Decode(imagemeta.Options{
		R: r, ImageFormat: imagemeta.TIFF, Sources: imagemeta.EXIF,
		LimitNumTags: 5000, LimitTagSize: 4,
		ShouldHandleTag: func(tag imagemeta.TagInfo) bool {
			return tag.Namespace == "IFD0" && (tag.Tag == "ImageWidth" || tag.Tag == "ImageHeight")
		},
		HandleTag: func(tag imagemeta.TagInfo) error {
			i := 0
			if tag.Tag == "ImageHeight" {
				i = 1
			}
			if seen[i] {
				return errMetadata
			}
			seen[i] = true
			switch v := tag.Value.(type) {
			case uint16:
				values[i] = int64(v)
			case uint32:
				values[i] = int64(v)
			default:
				return errMetadata
			}
			if values[i] <= 0 {
				return errMetadata
			}
			if seen[0] && seen[1] {
				return imagemeta.ErrStopWalking
			}
			return nil
		},
	})
	if err != nil {
		return image.Config{}, err
	}
	w, h := values[0], values[1]
	if w <= 0 || h <= 0 || uint64(w) > uint64(^uint(0)>>1) || uint64(h) > uint64(^uint(0)>>1) {
		return image.Config{}, errMetadata
	}
	return image.Config{Width: int(w), Height: int(h)}, nil
}
