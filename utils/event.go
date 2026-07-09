// Package utils holds small helpers shared across this SDK's NIP and
// relay packages: event/tag validation, key management, NIP-05/LUD-16
// URL helpers, logging, and LNURL decoding. It has no NIP of its own — it
// exists to avoid duplicating this plumbing in every package that needs it.
package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ohstr/nmilat/nip16"
	"github.com/ohstr/nmilat/nip33"
	"strconv"
	"strings"
	"unicode"
)

var (
	ErrTagNotFound  = errors.New("tag not found")
	ErrTagNotUnique = errors.New("multiple tags with the same name found")
)

func ValidateKind(kind int) error {
	if kind < 0 || kind > 65535 {
		return fmt.Errorf("kind must be an integer between 0 and 65535, got=%d", kind)
	}
	return nil
}

func ValidateStrKind(skind string) (int, error) {
	kind, err := strconv.Atoi(skind)
	if err != nil {
		return -1, err
	}
	if kind < 0 || kind > 65535 {
		return -1, fmt.Errorf("kind must be an integer between 0 and 65535, got=%d", kind)
	}
	return kind, nil
}

func ValidateEventTags(tags [][]string) error {
	for _, tag := range tags {
		if len(tag) == 0 {
			return fmt.Errorf("invalid tag")
		}
	}
	return nil
}

func LookupEventTag(tags [][]string, tagName string) ([][]string, bool) {
	var result [][]string
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == tagName {
			result = append(result, tag)
		}
	}
	if len(result) == 0 {
		return nil, false
	}
	return result, true
}

func FindUniqueEventTag(tags [][]string, tagName string) ([]string, error) {
	var found []string
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == tagName {
			if found != nil {
				return nil, ErrTagNotUnique
			}
			found = tag
		}
	}
	if found == nil {
		return nil, ErrTagNotFound
	}
	return found, nil
}

func FindUniqueEventTagValue(tags [][]string, tagName string) (string, error) {
	tag, err := FindUniqueEventTag(tags, tagName)
	if err != nil {
		return "", err
	}
	if len(tag) < 2 {
		return "", errors.New("tag does not have a value")
	}
	return tag[1], nil
}

func ValidateIndexableTag(name string) error {
	if len(name) != 1 {
		return fmt.Errorf("indexable tag name must be a single letter, got=%s", name)
	}
	if !unicode.IsLetter(rune(name[0])) {
		return fmt.Errorf("indexable tag name must be a-z|A-Z, got=%s", name)
	}
	return nil
}

func ValidateFilterTags(tags map[string][]string) error {
	for name, vals := range tags {
		if err := ValidateFilterTag(name, vals); err != nil {
			return err
		}
	}
	return nil
}

func ValidateFilterTag(name string, vals []string) error {
	if len(vals) == 0 {
		return fmt.Errorf("no tag values provided, at least one tag value is required")
	}

	if name == "e" || name == "p" {
		if err := Validate32Key(vals[0]); err != nil {
			return fmt.Errorf("tag e|p must contain 64 char lowercase hex values: %w", err)
		}
		return nil
	}

	return ValidateIndexableTag(name)
}

func ParseATag(tag string) (kind int, pubKey, dValue string, err error) {

	items := strings.Split(tag, ":")
	if len(items) != 3 {
		err = fmt.Errorf("bad length %d", len(items))
		return
	}
	kind, err = strconv.Atoi(items[0])
	if err != nil {
		return
	}
	err = ValidateKind(kind)
	if err != nil {
		return
	}

	if !nip16.IsReplaceableKind(kind) && !nip33.IsParamReplaceableKind(kind) {
		err = fmt.Errorf("%d is not a replaceable kind %v", kind, nip16.IsReplaceableKind(kind))
		return
	}

	pubKey = items[1]
	err = Validate32Key(pubKey)
	if err != nil {
		return
	}

	return kind, pubKey, items[2], nil
}

const hexDigits = "0123456789abcdef"

// hexDigit returns the lowercase hex character for nibble (0-15).
func hexDigit(nibble byte) byte {
	return hexDigits[nibble]
}

func EscapeJSONString(s string) string {
	estimatedSize := len(s) * 2
	var buf bytes.Buffer
	buf.Grow(estimatedSize)

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if s[i] < 0x20 { // Unicode escaping for control characters
				// s[i] < 0x20, so this is always exactly 4 hex digits total:
				// "00" + one of "0"-"1" + one hex nibble.
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigit(s[i] >> 4))
				buf.WriteByte(hexDigit(s[i] & 0xF))
			} else {
				buf.WriteByte(s[i])
			}
		}
	}

	return buf.String()
}

func MarshalTags(tags [][]string) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(tags); err != nil {
		return nil, fmt.Errorf("failed serializing tags=%v, %w", tags, err)
	}

	bytes := buffer.Bytes()
	if len(bytes) > 0 && bytes[len(bytes)-1] == '\n' {
		bytes = bytes[:len(bytes)-1] // remove the last newline if exists
	}

	return bytes, nil
}
