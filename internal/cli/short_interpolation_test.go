// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"
)

func TestShortOutsideInterpolationStaysWithheld(t *testing.T) {
	for _, value := range []string{"on", "1", "true"} {
		proj, outside := outsideLayout(t, "services: {api: {image: nginx, environment: {V: '${OUTSIDE_PLAIN}'}, command: ['echo', 'prefix${OUTSIDE_PLAIN}suffix']}}\n")
		if err := os.WriteFile(outside, []byte("OUTSIDE_PLAIN="+value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"inspect", "--json"}, {"explain", "--all", "--json"}, {"explain", "api:V", "--json"}, {"report", "--json", "--no-engine"}} {
			code, out, errs := runIn(t, proj, nil, append(args, "--env-file", outside)...)
			if code != 0 {
				t.Errorf("%v value=%q exit=%d stderr=%s", args, value, code, errs)
			}
			for _, text := range decodedStrings([]byte(out)) {
				if text == value || text == "prefix"+value+"suffix" {
					t.Errorf("%v exposed interpolated short outside value %q", args, value)
				}
			}
		}
	}
}
