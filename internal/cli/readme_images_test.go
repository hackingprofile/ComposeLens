// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The README terminal images are rendered from the real CLI output on
// examples/readme-demo. This test renders them again and requires the
// committed SVGs to match, so the images cannot drift from the product.
// COMPOSELENS_UPDATE_GOLDEN=1 rewrites them.
func TestReadmeTerminalImagesMatchTheDemo(t *testing.T) {
	root := chdirRoot(t)
	demo := filepath.Join(root, "examples", "readme-demo")
	update := os.Getenv("COMPOSELENS_UPDATE_GOLDEN") == "1"
	for _, img := range []struct {
		file string
		args []string
	}{
		{"explain.svg", []string{"explain", "api:APP_ENV"}},
		{"check.svg", []string{"check"}},
	} {
		code, out, errb := runCLI(t, demo, img.args)
		if code != 0 {
			t.Fatalf("%v: exit %d %s", img.args, code, errb)
		}
		text := portableOutput(string(out), root)
		svg := terminalSVG("cd examples/readme-demo && composelens "+strings.Join(img.args, " "), text)
		path := filepath.Join(root, "docs", "assets", img.file)
		if update {
			if err := os.WriteFile(path, []byte(svg), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (set COMPOSELENS_UPDATE_GOLDEN=1 once)", img.file, err)
		}
		if string(raw) != svg {
			t.Errorf("docs/assets/%s no longer matches `composelens %s` on examples/readme-demo; re-render it", img.file, strings.Join(img.args, " "))
		}
	}
}

// portableOutput replaces the checkout path with ~/composelens and uses
// forward slashes in it, so the image is the same on every machine.
func portableOutput(s, root string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if j := strings.Index(l, root); j >= 0 {
			rest := strings.ReplaceAll(l[j+len(root):], `\`, "/")
			l = l[:j] + "~/composelens" + rest
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

func xmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// terminalSVG draws a dark terminal window: a title bar, the prompt line and
// the output, in a monospace font. The canvas is sized to the longest line.
func terminalSVG(command, output string) string {
	const (
		font   = 13
		charW  = 8.0 // a little wider than common monospace advances, so no line is cut
		lineH  = 18
		padX   = 18
		titleH = 30
	)
	lines := append([]string{"$ " + command, ""}, strings.Split(output, "\n")...)
	longest := 0
	for _, l := range lines {
		if n := len([]rune(l)); n > longest {
			longest = n
		}
	}
	width := int(float64(longest)*charW) + 2*padX
	height := titleH + 14 + len(lines)*lineH + 14
	var b strings.Builder
	fmt.Fprintf(&b, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\">\n", width, height, width, height)
	fmt.Fprintf(&b, "<title>%s</title>\n", xmlText("composelens output: "+command))
	fmt.Fprintf(&b, "<rect width=\"%d\" height=\"%d\" rx=\"10\" fill=\"#0d1626\"/>\n", width, height)
	fmt.Fprintf(&b, "<rect width=\"%d\" height=\"%d\" rx=\"10\" fill=\"#18243a\"/>\n<rect y=\"20\" width=\"%d\" height=\"%d\" fill=\"#18243a\"/>\n", width, titleH, width, titleH-20)
	for i, c := range []string{"#ff5f57", "#febc2e", "#28c840"} {
		fmt.Fprintf(&b, "<circle cx=\"%d\" cy=\"15\" r=\"6\" fill=\"%s\"/>\n", 20+i*20, c)
	}
	fmt.Fprintf(&b, "<g font-family=\"ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace\" font-size=\"%d\" xml:space=\"preserve\">\n", font)
	for i, l := range lines {
		color := "#d6e2f5"
		if i == 0 {
			color = "#7fd1ff"
		}
		fmt.Fprintf(&b, "<text x=\"%d\" y=\"%d\" fill=\"%s\">%s</text>\n", padX, titleH+14+(i+1)*lineH-4, color, xmlText(l))
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}
