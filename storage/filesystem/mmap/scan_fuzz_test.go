//go:build darwin || linux

package mmap

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-billy/v6"
	fixtures "github.com/go-git/go-git-fixtures/v6"

	"github.com/go-git/go-git/v6/plumbing"
)

func FuzzValidateIdx(f *testing.F) {
	for _, format := range []string{"sha1", "sha256"} {
		idx, err := fixtures.ByTag("packfile").ByObjectFormat(format).One().Idx()
		if err != nil {
			f.Fatal(err)
		}
		data, err := io.ReadAll(idx)
		_ = idx.Close()
		if err != nil {
			f.Fatal(err)
		}
		isSHA256 := format == "sha256"

		f.Add(data, isSHA256)
		f.Add(data, !isSHA256)
		f.Add(data[:len(data)-1], isSHA256)

		lastFanout := idxHeaderSize + idxFanoutSize - 4
		huge := bytes.Clone(data)
		binary.BigEndian.PutUint32(huge[lastFanout:], 0xffffffff)
		f.Add(huge, isSHA256)

		unordered := bytes.Clone(data)
		binary.BigEndian.PutUint32(unordered[idxHeaderSize:], binary.BigEndian.Uint32(data[lastFanout:])+1)
		f.Add(unordered, isSHA256)
	}
	f.Add([]byte{0xff, 't', 'O', 'c', 0, 0, 0, 2}, false)
	f.Add([]byte{}, false)

	f.Fuzz(func(t *testing.T, data []byte, isSHA256 bool) {
		hashSize := crypto.SHA1.Size()
		if isSHA256 {
			hashSize = crypto.SHA256.Size()
		}

		count, err := validateIdx(data, hashSize)
		if err != nil {
			return
		}

		// Lookups slice the names, CRC and 32-bit offset tables at
		// positions derived from count, and read both trailing checksums,
		// so an accepted idx must hold all of them.
		need := idxHeaderSize + idxFanoutSize + count*(hashSize+idxCrcSize+off32Size) + 2*hashSize
		if count < 0 || need > len(data) {
			t.Fatalf("accepted idx of %d bytes declaring %d objects, which need at least %d bytes", len(data), count, need)
		}
	})
}

func FuzzPackScanner(f *testing.F) {
	for _, format := range []string{"sha1", "sha256"} {
		fixture := fixtures.ByTag("packfile").ByObjectFormat(format).One()
		read := func(file billy.File, err error) []byte {
			if err != nil {
				f.Fatal(err)
			}
			defer file.Close()
			data, err := io.ReadAll(file)
			if err != nil {
				f.Fatal(err)
			}
			return data
		}
		pack := read(fixture.Packfile())
		idx := read(fixture.Idx())
		rev := read(fixture.Rev())
		f.Add(pack, idx, rev, format == "sha256")
	}

	f.Fuzz(func(t *testing.T, pack, idx, rev []byte, isSHA256 bool) {
		hashSize := crypto.SHA1.Size()
		if isSHA256 {
			hashSize = crypto.SHA256.Size()
		}

		dir := t.TempDir()
		open := func(name string, data []byte) *os.File {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			return file
		}

		s, err := NewPackScanner(hashSize, open("pack", pack), open("idx", idx), open("rev", rev))
		if err != nil {
			return
		}
		defer s.Close()

		missing, _ := plumbing.FromBytes(make([]byte, hashSize))
		_, _ = s.Get(missing)
		_, _ = s.GetByOffset(0)
		_, _ = s.GetByOffset(uint64(len(pack)))

		for i := range min(s.count, 64) {
			name := s.idxMmap[s.namesStart+i*hashSize : s.namesStart+(i+1)*hashSize]
			id, ok := plumbing.FromBytes(name)
			if !ok {
				continue
			}

			offset, err := s.FindOffset(id)
			if err != nil {
				continue
			}
			_, _ = s.FindHash(offset)
			_, _ = s.GetByOffset(offset)

			obj, err := s.Get(id)
			if err != nil {
				continue
			}
			r, err := obj.Reader()
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
			_ = r.Close()
		}
	})
}
