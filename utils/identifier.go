package utils

import "strings"

// ParseIdentifier splits a NIP-05 or LUD-16 internet identifier
// ("name@domain") into its lowercased name and domain. It trims
// surrounding whitespace and accepts any TLD length; ok is false when the
// name or domain isn't valid.
func ParseIdentifier(id string) (name, domain string, ok bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	at := strings.LastIndexByte(id, '@')
	if at <= 0 || at == len(id)-1 {
		return "", "", false
	}
	name, domain = id[:at], id[at+1:]
	if !validLocalPart(name) || !validHostname(domain) {
		return "", "", false
	}
	return name, domain, true
}

// validLocalPart allows the NIP-05 set (a-z0-9-_.) plus LUD-16's "+".
func validLocalPart(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == '+':
		default:
			return false
		}
	}
	return s != ""
}

// validHostname requires at least two labels of a-z0-9 and inner hyphens,
// with an alphabetic (or punycode) TLD.
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		return true
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return len(tld) >= 2
}
