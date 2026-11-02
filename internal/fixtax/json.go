// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"encoding/json"
	"runtime"
)

func jsonUnmarshal(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}

func EncodeReport(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func currentGOOS() string {
	return runtime.GOOS
}
