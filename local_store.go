package tuf

import (
	"bytes"
	"encoding/json"
	"github.com/flynn/go-tuf/keystore"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/util"
)

func MemoryStore(meta map[string]json.RawMessage, files map[string][]byte) LocalStore {
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}
	return &memoryStore{
		meta:    meta,
		files:   files,
		signers: make(map[string][]keystore.Signer),
	}
}

var _ LocalStore = &memoryStore{}
type memoryStore struct {
	meta    map[string]json.RawMessage
	files   map[string][]byte
	signers map[string][]keystore.Signer
}

func (m *memoryStore) GetMeta() (map[string]json.RawMessage, error) {
	return m.meta, nil
}

func (m *memoryStore) SetMeta(name string, meta json.RawMessage) error {
	m.meta[name] = meta
	return nil
}

func (m *memoryStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		for path, data := range m.files {
			if err := targetsFn(path, bytes.NewReader(data)); err != nil {
				return err
			}
		}
		return nil
	}

	for _, path := range paths {
		data, ok := m.files[path]
		if !ok {
			return ErrFileNotFound{path}
		}
		if err := targetsFn(path, bytes.NewReader(data)); err != nil {
			return err
		}
	}
	return nil
}

func (m *memoryStore) Commit(map[string]json.RawMessage, bool, map[string]data.Hashes) error {
	return nil
}

func (m *memoryStore) Clean() error {
	return nil
}

func FileSystemStore(dir string) LocalStore {
	return &fileSystemStore{
		dir:            dir,
	}
}

type fileSystemStore struct {
	dir            string
}

func (f *fileSystemStore) repoDir() string {
	return filepath.Join(f.dir, "repository")
}

func (f *fileSystemStore) stagedDir() string {
	return filepath.Join(f.dir, "staged")
}

func (f *fileSystemStore) GetMeta() (map[string]json.RawMessage, error) {
	meta := make(map[string]json.RawMessage)
	var err error
	notExists := func(path string) bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}
	for _, name := range topLevelManifests {
		path := filepath.Join(f.stagedDir(), name)
		if notExists(path) {
			path = filepath.Join(f.repoDir(), name)
			if notExists(path) {
				continue
			}
		}
		meta[name], err = ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	return meta, nil
}

func (f *fileSystemStore) SetMeta(name string, meta json.RawMessage) error {
	if err := f.createDirs(); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(f.stagedDir(), name), meta, 0644); err != nil {
		return err
	}
	return nil
}

func (f *fileSystemStore) createDirs() error {
	for _, dir := range []string{"keys", "repository", "staged/targets"} {
		if err := os.MkdirAll(filepath.Join(f.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSystemStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		walkFunc := func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(filepath.Join(f.stagedDir(), "targets"), path)
			if err != nil {
				return err
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			return targetsFn(rel, file)
		}
		return filepath.Walk(filepath.Join(f.stagedDir(), "targets"), walkFunc)
	}

	// check all the files exist before processing any files
	for _, path := range paths {
		realPath := filepath.Join(f.stagedDir(), "targets", path)
		if _, err := os.Stat(realPath); err != nil {
			if os.IsNotExist(err) {
				return ErrFileNotFound{realPath}
			}
			return err
		}
	}

	for _, path := range paths {
		realPath := filepath.Join(f.stagedDir(), "targets", path)
		file, err := os.Open(realPath)
		if err != nil {
			if os.IsNotExist(err) {
				return ErrFileNotFound{realPath}
			}
			return err
		}
		err = targetsFn(path, file)
		file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSystemStore) createRepoFile(path string) (*os.File, error) {
	dst := filepath.Join(f.repoDir(), path)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return nil, err
	}
	return os.Create(dst)
}

func (f *fileSystemStore) Commit(meta map[string]json.RawMessage, consistentSnapshot bool, hashes map[string]data.Hashes) error {
	isTarget := func(path string) bool {
		return strings.HasPrefix(path, "targets/")
	}
	shouldCopyHashed := func(path string) bool {
		return consistentSnapshot && path != "timestamp.json"
	}
	shouldCopyUnhashed := func(path string) bool {
		return !consistentSnapshot || !isTarget(path)
	}
	copyToRepo := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(f.stagedDir(), path)
		if err != nil {
			return err
		}
		var paths []string
		if shouldCopyHashed(rel) {
			paths = append(paths, util.HashedPaths(rel, hashes[rel])...)
		}
		if shouldCopyUnhashed(rel) {
			paths = append(paths, rel)
		}
		var files []io.Writer
		for _, path := range paths {
			file, err := f.createRepoFile(path)
			if err != nil {
				return err
			}
			defer file.Close()
			files = append(files, file)
		}
		staged, err := os.Open(path)
		if err != nil {
			return err
		}
		defer staged.Close()
		if _, err = io.Copy(io.MultiWriter(files...), staged); err != nil {
			return err
		}
		return nil
	}
	needsRemoval := func(path string) bool {
		if consistentSnapshot {
			// strip out the hash
			name := strings.SplitN(filepath.Base(path), ".", 2)
			if len(name) != 2 || name[1] == "" {
				return false
			}
			path = filepath.Join(filepath.Dir(path), name[1])
		}
		_, ok := hashes[path]
		return !ok
	}
	removeFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(f.repoDir(), path)
		if err != nil {
			return err
		}
		if !info.IsDir() && isTarget(rel) && needsRemoval(rel) {
			if err := os.Remove(path); err != nil {
				// TODO: log / handle error
			}
			// TODO: remove empty directory
		}
		return nil
	}
	if err := filepath.Walk(f.stagedDir(), copyToRepo); err != nil {
		return err
	}
	if err := filepath.Walk(f.repoDir(), removeFile); err != nil {
		return err
	}
	return f.Clean()
}


func (f *fileSystemStore) Clean() error {
	_, err := os.Stat(filepath.Join(f.repoDir(), "root.json"))
	if os.IsNotExist(err) {
		return ErrNewRepository
	} else if err != nil {
		return err
	}
	if err := os.RemoveAll(f.stagedDir()); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(f.stagedDir(), "targets"), 0755)
}
