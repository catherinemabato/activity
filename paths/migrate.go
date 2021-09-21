// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package paths

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// TryConfigFileMigration carefully copies the contents of oldFile to
// newFile, returning the path which should be used to read the config.
// - if newFile already exists, don't modify it just return its path
// - if neither oldFile nor newFile exist, return newFile for a fresh
//   default config to be written to.
// - if oldFile exists but copying to newFile fails, return oldFile so
//   there will at least be some config to work with.
func TryConfigFileMigration(oldFile, newFile string) string {
	_, err := os.Stat(newFile)
	if err == nil {
		// Common case for a system which has already been migrated.
		return newFile
	}
	if !os.IsNotExist(err) {
		log.Printf("TryConfigFileMigration failed; new file: %v", err)
		return newFile
	}

	contents, err := os.ReadFile(oldFile)
	if err != nil {
		// Common case for a new user.
		return newFile
	}

	newDir := filepath.Dir(newFile)
	os.MkdirAll(newDir, 0700)

	if runtime.GOOS == "windows" {
		err = SetStateDirPerms(newDir)
		if err != nil {
			return oldFile
		}
	}

	err = os.WriteFile(newFile, contents, 0600)
	if err != nil {
		removeErr := os.Remove(newFile)
		if removeErr != nil {
			log.Printf("TryConfigFileMigration failed; write newFile no cleanup: %v, remove err: %v",
				err, removeErr)
			return oldFile
		}
		log.Printf("TryConfigFileMigration failed; write newFile: %v", err)
		return oldFile
	}

	log.Printf("TryConfigFileMigration: successfully migrated: from %v to %v",
		oldFile, newFile)

	return newFile
}
