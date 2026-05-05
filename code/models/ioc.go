package models

import (
	"net/netip"
	"regexp"
	"strings"
)

// detectHashType identifies the hash algorithm based on hex string length
// MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
func detectHashType(hash string) string {
	// Only process valid hex strings
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "unknown"
		}
	}

	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "unknown"
	}
}

// isMD5 checks if hash is a valid MD5 (32 hex chars)
func isMD5(hash string) bool {
	return detectHashType(hash) == "md5"
}

// isSHA1 checks if hash is a valid SHA1 (40 hex chars)
func isSHA1(hash string) bool {
	return detectHashType(hash) == "sha1"
}

// isSHA256 checks if hash is a valid SHA256 (64 hex chars)
func isSHA256(hash string) bool {
	return detectHashType(hash) == "sha256"
}

func isIPv4(ioc string) bool {
	addr, err := netip.ParseAddr(ioc)
	return err == nil && addr.Is4()
}

func isIPv6(ioc string) bool {
	addr, err := netip.ParseAddr(ioc)
	return err == nil && addr.Is6()
}

var DomainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func isDomain(domain string) bool {
	return DomainRegex.MatchString(domain)
}

func IOCClassifier(data string) string {
	value := strings.TrimSpace(data)

	switch {
	case isIPv4(value):
		return "IPv4"
	case isIPv6(value):
		return "IPv6"
	case isMD5(value):
		return "MD5"
	case isSHA1(value):
		return "SHA1"
	case isSHA256(value):
		return "SHA256"
	case isDomain(value):
		return "Domain"
	default:
		return "Domain"
	}
}
