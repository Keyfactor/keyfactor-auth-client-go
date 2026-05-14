// Copyright 2026 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

// configFileExtensions is the discovery order applied to
// ~/.keyfactor/command_config.* when no explicit path is provided.
// JSON-first preserves the existing kfc-auth convention; YAML variants
// are checked next.
var configFileExtensions = []string{".json", ".yaml", ".yml"}

// discoverConfigFile resolves the file path the loader should read.
//
// Returns ("", nil) when no config file is found anywhere; that's not
// an error — callers can still produce a complete Server from env vars
// and flags alone.
func (l *Loader) discoverConfigFile() (string, error) {
	// 0. CLI flag override (bound by bindFlags into "active_config_file").
	if l.opts.flagSet != nil {
		if f := l.opts.flagSet.Lookup("config-file"); f != nil && f.Changed {
			path := f.Value.String()
			if _, err := os.Stat(path); err != nil {
				return "", fmt.Errorf("config file %q (--config-file) not readable: %w", path, err)
			}
			return path, nil
		}
		if f := l.opts.flagSet.Lookup("config"); f != nil && f.Changed {
			path := f.Value.String()
			if _, err := os.Stat(path); err != nil {
				return "", fmt.Errorf("config file %q (--config) not readable: %w", path, err)
			}
			return path, nil
		}
	}

	// 1. Explicit option.
	if l.opts.configFile != "" {
		if _, err := os.Stat(l.opts.configFile); err != nil {
			return "", fmt.Errorf("config file %q not readable: %w", l.opts.configFile, err)
		}
		return l.opts.configFile, nil
	}

	// 2. Env override (uses kfc-auth's existing constant).
	if envPath := os.Getenv(auth_providers.EnvKeyfactorConfigFile); envPath != "" {
		if _, err := os.Stat(envPath); err != nil {
			return "", fmt.Errorf("config file %q (from %s) not readable: %w",
				envPath, auth_providers.EnvKeyfactorConfigFile, err)
		}
		return envPath, nil
	}

	// 3. Default search path: ~/.keyfactor/command_config.<ext>.
	home, err := os.UserHomeDir()
	if err != nil {
		// No home dir is not fatal — caller may be running in a
		// minimal container where everything comes from env vars.
		return "", nil
	}
	dir := filepath.Join(home, ".keyfactor")
	for _, ext := range configFileExtensions {
		candidate := filepath.Join(dir, "command_config"+ext)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", nil
}
