package xxe

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// defaultBody is what a run sends when the operator supplies no XML of their
// own. It is a plain, well-formed document with one text value, so every
// module still has an injection point to work with.
const defaultBody = `<?xml version="1.0" encoding="UTF-8"?>
<aperture-probe><input>aperture-xxe-probe</input></aperture-probe>`

// doctypePattern matches a document type declaration, including an internal
// subset in square brackets. Any DOCTYPE the operator supplied is removed
// before the scanner adds its own, since a document can only carry one.
var doctypePattern = regexp.MustCompile(`(?s)<!DOCTYPE\b[^\[>]*(\[.*?\])?\s*>`)

// leaf is one injection point: a text value that sits directly inside an
// element. start and end are byte offsets into template.text, so a payload
// can replace exactly that value and leave the rest of the document alone.
type leaf struct {
	index   int
	start   int
	end     int
	element string
}

// template is the operator's XML (or defaultBody) with any DOCTYPE removed,
// plus every leaf it contains. Each payload is rendered from a template
// rather than from the raw input, so offsets always line up.
type template struct {
	text string
	// declEnd is the byte offset just past the <?xml ...?> declaration, or 0
	// when there isn't one. A DOCTYPE must follow the declaration, so it goes
	// here.
	declEnd int
	leaves  []leaf
}

// parseTemplate checks that raw is well-formed XML, strips any DOCTYPE from
// it, and records every leaf text value. It returns an error when the input
// is malformed or has no text value to inject into.
func parseTemplate(raw string) (template, error) {
	stripped := doctypePattern.ReplaceAllString(raw, "")

	t := template{text: stripped}
	// The declaration has to be the very first thing in the document, so a
	// plain prefix check is enough to find it.
	if strings.HasPrefix(stripped, "<?xml") {
		if i := strings.Index(stripped, "?>"); i >= 0 {
			t.declEnd = i + len("?>")
		}
	}

	dec := xml.NewDecoder(strings.NewReader(stripped))
	var stack []string
	// pending holds a text value seen but not yet confirmed as a leaf. Text
	// only counts when the very next token closes its element, which rules
	// out mixed content and text followed by a comment or child element.
	var pending *leaf
	for {
		// InputOffset before Token gives the byte where the next token
		// starts, which is what a text value's range needs.
		tokStart := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return template{}, fmt.Errorf("body is not well-formed XML: %w", err)
		}
		tokEnd := dec.InputOffset()

		switch v := tok.(type) {
		case xml.StartElement:
			pending = nil
			stack = append(stack, v.Name.Local)
		case xml.CharData:
			pending = nil
			// Go's decoder hands CDATA back as CharData too, but its raw
			// bytes start with "<". Replacing those would break the section,
			// so only plain text is a candidate.
			raw := stripped[tokStart:tokEnd]
			if len(stack) > 0 && strings.TrimSpace(string(v)) != "" && !strings.HasPrefix(raw, "<") {
				pending = &leaf{start: int(tokStart), end: int(tokEnd), element: stack[len(stack)-1]}
			}
		case xml.EndElement:
			if pending != nil {
				pending.index = len(t.leaves)
				t.leaves = append(t.leaves, *pending)
				pending = nil
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			pending = nil
		}
	}

	if len(t.leaves) == 0 {
		return template{}, fmt.Errorf("body has no element with a text value to inject into")
	}
	return t, nil
}

// render builds one XML document from the template. When pt is non-nil its
// text value is replaced by replacement; when doctype is non-empty it is
// placed before the root element.
func (t template) render(pt *leaf, replacement, doctype string) string {
	body := t.text
	if pt != nil {
		// Splice at the leaf first. The declaration sits before every leaf,
		// so declEnd is still valid after this edit.
		body = body[:pt.start] + replacement + body[pt.end:]
	}
	if doctype != "" {
		body = body[:t.declEnd] + doctype + body[t.declEnd:]
	}
	return body
}

// describe names a leaf for finding labels, e.g. `<username>`.
func (l leaf) describe() string {
	return fmt.Sprintf("<%s>", l.element)
}
