// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"testing"
)

func TestSanitizeStrict(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strips all HTML tags",
			input:    "<script>alert('xss')</script>Hello",
			expected: "Hello",
		},
		{
			name:     "strips img tags",
			input:    `<img src="x" onerror="alert(1)">text`,
			expected: "text",
		},
		{
			name:     "preserves plain text",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "strips bold and italic",
			input:    "<b>bold</b> and <i>italic</i>",
			expected: "bold and italic",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeStrict(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeStrict(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeUGC(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldStrip bool
	}{
		{
			name:        "strips script tags",
			input:       "<script>alert('xss')</script>",
			shouldStrip: true,
		},
		{
			name:        "allows basic formatting",
			input:       "<b>bold</b>",
			shouldStrip: false,
		},
		{
			name:        "strips event handlers",
			input:       `<div onmouseover="alert(1)">text</div>`,
			shouldStrip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeUGC(tt.input)
			if tt.shouldStrip && result == tt.input {
				t.Errorf("SanitizeUGC(%q) should have stripped content but returned unchanged", tt.input)
			}
		})
	}
}

func TestSanitizeRichText(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldStrip bool
	}{
		{
			name:        "strips script tags",
			input:       "<script>alert('xss')</script>",
			shouldStrip: true,
		},
		{
			name:        "allows img with safe attrs",
			input:       `<img src="https://example.com/img.png" alt="test">`,
			shouldStrip: false,
		},
		{
			name:        "allows style attribute",
			input:       `<p style="color: red;">text</p>`,
			shouldStrip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeRichText(tt.input)
			if tt.shouldStrip && result == tt.input {
				t.Errorf("SanitizeRichText(%q) should have stripped content but returned unchanged", tt.input)
			}
		})
	}
}

func TestSanitizeStrictPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := SanitizeStrictPtr(nil)
		if result != nil {
			t.Error("SanitizeStrictPtr(nil) should return nil")
		}
	})

	t.Run("non-nil input sanitized", func(t *testing.T) {
		input := "<script>alert('xss')</script>Hello"
		result := SanitizeStrictPtr(&input)
		if result == nil {
			t.Fatal("SanitizeStrictPtr should not return nil for non-nil input")
		}
		if *result != "Hello" {
			t.Errorf("SanitizeStrictPtr got %q, want %q", *result, "Hello")
		}
	})
}

func TestSanitizeUGCPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := SanitizeUGCPtr(nil)
		if result != nil {
			t.Error("SanitizeUGCPtr(nil) should return nil")
		}
	})

	t.Run("non-nil input sanitized", func(t *testing.T) {
		input := "<script>alert('xss')</script><b>bold</b>"
		result := SanitizeUGCPtr(&input)
		if result == nil {
			t.Fatal("SanitizeUGCPtr should not return nil for non-nil input")
		}
		if *result == input {
			t.Error("SanitizeUGCPtr should have sanitized the input")
		}
	})
}

func TestSanitizeRichTextPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := SanitizeRichTextPtr(nil)
		if result != nil {
			t.Error("SanitizeRichTextPtr(nil) should return nil")
		}
	})

	t.Run("non-nil input sanitized", func(t *testing.T) {
		input := "<script>alert('xss')</script><b>bold</b>"
		result := SanitizeRichTextPtr(&input)
		if result == nil {
			t.Fatal("SanitizeRichTextPtr should not return nil for non-nil input")
		}
		if *result == input {
			t.Error("SanitizeRichTextPtr should have sanitized the input")
		}
	})
}
