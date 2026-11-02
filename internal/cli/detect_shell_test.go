// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"composelens/internal/evidence"
)

func TestDetectShellDistinguishesWindowsFamilies(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(k string) string { return values[k] }
	}
	shell, cert := detectShellUsing("windows", getenv(map[string]string{"ComSpec": `C:\Windows\system32\cmd.exe`}))
	if shell != "cmd" || cert != evidence.Inferred {
		t.Fatalf("cmd: %s %s", shell, cert)
	}
	shell, cert = detectShellUsing("windows", getenv(map[string]string{
		"PSModulePath": `C:\Users\demo\Documents\WindowsPowerShell\Modules;C:\Windows\System32\WindowsPowerShell\v1.0\Modules`,
		"ComSpec":      `C:\Windows\system32\cmd.exe`,
	}))
	if shell != "powershell" || cert != evidence.Inferred {
		t.Fatalf("powershell: %s %s", shell, cert)
	}
	shell, cert = detectShellUsing("windows", getenv(map[string]string{
		"PSModulePath":                    `C:\Program Files\PowerShell\7\Modules`,
		"POWERSHELL_DISTRIBUTION_CHANNEL": "PSCore",
		"ComSpec":                         `C:\Windows\system32\cmd.exe`,
	}))
	if shell != "pwsh" || cert != evidence.Inferred {
		t.Fatalf("pwsh: %s %s", shell, cert)
	}
	shell, cert = detectShellUsing("linux", getenv(map[string]string{"SHELL": "/bin/zsh"}))
	if shell != "zsh" || cert != evidence.Proven {
		t.Fatalf("unix: %s %s", shell, cert)
	}
}
