// SPDX-License-Identifier: Apache-2.0

// Package sanitizer provides HTML sanitization utilities for user-provided content.
package sanitizer

import "github.com/microcosm-cc/bluemonday"

var (
	strictPolicy   *bluemonday.Policy
	ugcPolicy      *bluemonday.Policy
	richTextPolicy *bluemonday.Policy
)

func init() {
	strictPolicy = bluemonday.StrictPolicy()

	ugcPolicy = bluemonday.UGCPolicy()
	ugcPolicy.AllowAttrs("class").Globally()
	ugcPolicy.AllowAttrs("id").Globally()

	richTextPolicy = bluemonday.UGCPolicy()
	richTextPolicy.AllowAttrs("class", "id", "style").Globally()
	richTextPolicy.AllowAttrs("src", "alt", "width", "height", "loading").OnElements("img")
	richTextPolicy.AllowAttrs("href", "target", "rel").OnElements("a")
	richTextPolicy.AllowElements("figure", "figcaption", "picture", "source")
	richTextPolicy.AllowStyles(
		"color",
		"background-color",
		"font-size",
		"font-weight",
		"font-style",
		"text-align",
		"text-decoration",
		"margin",
		"padding",
		"border",
		"width",
		"height",
		"max-width",
		"max-height",
	).Globally()
	richTextPolicy.AllowURLSchemes("http", "https", "mailto")
	richTextPolicy.RequireNoFollowOnLinks(true)
	richTextPolicy.RequireNoReferrerOnLinks(true)
}

// StrictPolicy returns a policy that strips all HTML tags.
// Use for plain text fields like names, titles, subjects.
func StrictPolicy() *bluemonday.Policy {
	return strictPolicy
}

// UGCPolicy returns a policy that allows safe HTML subset for user-generated content.
// Use for comments, notes, and basic formatted text.
func UGCPolicy() *bluemonday.Policy {
	return ugcPolicy
}

// RichTextPolicy returns a policy that allows a broader HTML subset for rich text.
// Use for CMS content, knowledge base articles, email bodies.
func RichTextPolicy() *bluemonday.Policy {
	return richTextPolicy
}

// SanitizeStrict removes all HTML from input.
// Use for plain text fields: names, titles, subjects, slugs.
func SanitizeStrict(input string) string {
	return strictPolicy.Sanitize(input)
}

// SanitizeUGC allows safe HTML subset in input.
// Use for user-generated content: comments, notes, descriptions.
func SanitizeUGC(input string) string {
	return ugcPolicy.Sanitize(input)
}

// SanitizeRichText allows a broader safe HTML subset in input.
// Use for rich text: CMS pages, knowledge base articles, email templates.
func SanitizeRichText(input string) string {
	return richTextPolicy.Sanitize(input)
}

// SanitizeStrictPtr sanitizes a string pointer with strict policy.
// Returns nil if input is nil.
func SanitizeStrictPtr(input *string) *string {
	if input == nil {
		return nil
	}
	sanitized := SanitizeStrict(*input)
	return &sanitized
}

// SanitizeUGCPtr sanitizes a string pointer with UGC policy.
// Returns nil if input is nil.
func SanitizeUGCPtr(input *string) *string {
	if input == nil {
		return nil
	}
	sanitized := SanitizeUGC(*input)
	return &sanitized
}

// SanitizeRichTextPtr sanitizes a string pointer with rich text policy.
// Returns nil if input is nil.
func SanitizeRichTextPtr(input *string) *string {
	if input == nil {
		return nil
	}
	sanitized := SanitizeRichText(*input)
	return &sanitized
}
