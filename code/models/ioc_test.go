package models

import "testing"

func TestIOCClassifierCharacterization(t *testing.T) {
	const (
		md5    = "d41d8cd98f00b204e9800998ecf8427e"
		sha1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
		sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv4", input: "192.168.1.1", want: "IPv4"},
		{name: "IPv4 with surrounding whitespace", input: "  1.2.3.4\t", want: "IPv4"},
		{name: "IPv4 with newlines", input: "\n8.8.8.8\n", want: "IPv4"},
		{name: "IPv6", input: "2001:db8::1", want: "IPv6"},
		{name: "IPv6 loopback", input: "::1", want: "IPv6"},
		{name: "IPv6 with surrounding whitespace", input: "  ::1  ", want: "IPv6"},
		{name: "MD5 lowercase hex", input: md5, want: "MD5"},
		{name: "MD5 uppercase hex", input: "D41D8CD98F00B204E9800998ECF8427E", want: "MD5"},
		{name: "MD5 with surrounding whitespace", input: " " + md5 + " ", want: "MD5"},
		{name: "SHA1 lowercase hex", input: sha1, want: "SHA1"},
		{name: "SHA1 uppercase hex", input: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", want: "SHA1"},
		{name: "SHA256 lowercase hex", input: sha256, want: "SHA256"},
		{name: "SHA256 uppercase hex", input: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", want: "SHA256"},
		{name: "domain", input: "example.com", want: "Domain"},
		{name: "subdomain", input: "sub.domain.example.co.uk", want: "Domain"},
		{name: "hyphenated domain", input: "my-site.example.com", want: "Domain"},
		{name: "domain with surrounding whitespace", input: "  example.com  ", want: "Domain"},
		{name: "empty string falls back to Domain", input: "", want: "Domain"},
		{name: "whitespace only falls back to Domain", input: "   \t\n", want: "Domain"},
		{name: "arbitrary text falls back to Domain", input: "not-an-ioc", want: "Domain"},
		{name: "non-hex hash-length string falls back to Domain", input: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", want: "Domain"},
		{name: "hex string of unsupported length falls back to Domain", input: "0123456789abcdef0123456789abcde", want: "Domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IOCClassifier(tt.input); got != tt.want {
				t.Errorf("IOCClassifier(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
