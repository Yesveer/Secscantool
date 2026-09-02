// Package ui centralizes secscantool's terminal look-and-feel (banner,
// step spinners, section headers) so every command feels consistent.
package ui

import (
	"fmt"

	"github.com/pterm/pterm"
)

// Banner prints the secscantool startup banner.
func Banner() {
	s, _ := pterm.DefaultBigText.WithLetters(
		pterm.NewLettersFromStringWithStyle("secscan", pterm.NewStyle(pterm.FgCyan)),
		pterm.NewLettersFromStringWithStyle("tool", pterm.NewStyle(pterm.FgLightCyan)),
	).Srender()
	pterm.Println(s)
	// Left-aligned to sit under the (left-aligned) big text above. Centering
	// this line on the full terminal width — as pterm.DefaultCenter does —
	// pulls it away from the banner on any terminal wider than the art
	// itself, which is most terminals.
	pterm.Println(pterm.Gray("  multi-language code · dependency · container vulnerability scanner"))
	pterm.Println()
}

// Phase prints a numbered top-level phase header, e.g. "[2/5] Scanning dependencies".
func Phase(n, total int, text string) {
	pterm.DefaultSection.WithLevel(1).Println(fmt.Sprintf("[%d/%d] %s", n, total, text))
}

// Spinner starts a spinner with the given starting text.
func Spinner(text string) *pterm.SpinnerPrinter {
	sp, _ := pterm.DefaultSpinner.WithRemoveWhenDone(false).Start(text)
	return sp
}

// Step runs fn under a spinner labeled text, turning it into a ✓/✗ line
// once fn returns. If fn returns an error, the spinner reports failure and
// the error message is shown; the error is still returned to the caller.
func Step(text string, fn func(update func(string)) error) error {
	sp := Spinner(text)
	err := fn(func(msg string) { sp.UpdateText(msg) })
	if err != nil {
		sp.Fail(fmt.Sprintf("%s — %v", text, err))
		return err
	}
	sp.Success(text)
	return nil
}
