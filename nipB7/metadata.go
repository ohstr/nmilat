package nipB7

import "strconv"

// NIP94Tags builds the NIP-94-style file metadata tags BUD-08 says a server
// MAY return in a Blob Descriptor's "nip94" field (and a client MAY reuse
// when attaching the blob to a kind:1063 file-metadata event or an "imeta"
// tag elsewhere): "url", "x" (the sha256), "size", and "m" (MIME type, if
// known).
func NIP94Tags(d BlobDescriptor) [][]string {
	tags := [][]string{
		{"url", d.URL},
		{"x", d.Sha256},
		{"size", strconv.FormatInt(d.Size, 10)},
	}
	if d.Type != "" {
		tags = append(tags, []string{"m", d.Type})
	}
	return tags
}

// HashFromNIP94Tags extracts the sha256 hash from a NIP-94-style tag set
// (its "x" tag), reporting ok as false if none of the tags is a
// hash-shaped "x" tag.
func HashFromNIP94Tags(tags [][]string) (hash string, ok bool) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "x" && IsSHA256Hex(tag[1]) {
			return tag[1], true
		}
	}
	return "", false
}
