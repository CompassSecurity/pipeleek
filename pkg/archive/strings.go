package archive

import (
	"bytes"
)

const (
	// MinStringLength is the minimum length of a string to be considered printable
	// This matches the default behavior of the Unix strings command
	MinStringLength = 4
)

// ExtractPrintableStrings extracts printable ASCII and UTF-8 strings from binary data.
// It works similarly to the Unix 'strings' command, extracting sequences of printable
// characters that are at least minLength characters long.
// If minLength is 0, MinStringLength (4) is used as default.
func ExtractPrintableStrings(data []byte, minLength int) []byte {
	if minLength <= 0 {
		minLength = MinStringLength
	}

	var result bytes.Buffer
	var currentString bytes.Buffer

	for i := 0; i < len(data); i++ {
		b := data[i]

		// Check if the byte represents a printable ASCII character
		// We're strict here: only ASCII printable chars, tabs, newlines, and carriage returns
		if isPrintableByte(b) {
			currentString.WriteByte(b)
		} else {
			// Non-printable character encountered
			if currentString.Len() >= minLength {
				// Write the accumulated string followed by a newline
				result.Write(currentString.Bytes())
				result.WriteByte('\n')
			}
			currentString.Reset()
		}
	}

	// Handle any remaining string at the end
	if currentString.Len() >= minLength {
		result.Write(currentString.Bytes())
		result.WriteByte('\n')
	}

	return result.Bytes()
}

// isPrintableByte checks if a byte represents a printable ASCII character.
// This includes ASCII printable characters (32-126), tabs, newlines, and carriage returns.
// We use byte-level checking to match the behavior of the Unix strings command,
// which operates on bytes rather than UTF-8 runes.
func isPrintableByte(b byte) bool {
	// Accept tab, newline, and carriage return
	if b == '\t' || b == '\n' || b == '\r' {
		return true
	}

	// Accept ASCII printable characters (space through tilde)
	if b >= 32 && b <= 126 {
		return true
	}

	return false
}
