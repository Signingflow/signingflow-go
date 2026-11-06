//go:build unix

package signingflow

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readJailed(root, requested string, maxBytes int64) ([]byte, error) {
	if syscall.O_NOFOLLOW == 0 {
		return nil, errors.New("nofollow")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolved := filepath.Clean(filepath.Join(base, requested))
	parent := filepath.Dir(resolved)
	parentReal, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, err
	}
	if escapes(base, parentReal) {
		return nil, errors.New("outside root")
	}
	leaf := filepath.Base(resolved)
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, errors.New("outside root")
	}
	path := filepath.Join(parentReal, leaf)
	if escapes(base, path) || filepath.Clean(path) == filepath.Clean(base) {
		return nil, errors.New("outside root")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("not a file")
	}
	if uint64(info.Nlink) > 1 {
		return nil, errors.New("hard link")
	}
	if info.Size > maxBytes {
		return nil, errors.New("too large")
	}
	if info.Size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, info.Size)
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func escapes(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return true
	}
	if rel == "." {
		return false
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == ".." {
			return true
		}
	}
	return false
}
