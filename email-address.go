package faroe

import (
	"slices"
	"strings"
)

type EmailAddressCheckerInterface interface {
	// Returns true, nil if the email address is allowed and false, nil if not.
	CheckEmailAddress(emailAddress string) (bool, error)
}

// Implements [EmailAddressCheckerInterface].
// Allows all email addresses.
var AllowAllEmailAddresses = allowAllEmailAddressesStruct{}

type allowAllEmailAddressesStruct struct{}

func (allowAllEmailAddressesStruct) CheckEmailAddress(emailAddress string) (bool, error) {
	return true, nil
}

func verifyEmailAddressPattern(email string) bool {
	if len(email) > 100 {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPartAllowed := verifyEmailAddressLocalPart(parts[0])
	if !localPartAllowed {
		return false
	}
	domainPartAllowed := verifyEmailAddressDomainPart(parts[1])
	if !localPartAllowed {
		return false
	}
	return domainPartAllowed
}

func verifyEmailAddressLocalPart(localPart string) bool {
	if len(localPart) < 1 {
		return false
	}
	allowedSpecialCharacters := []rune{'!', '#', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '{', '|', '}', '~', '.'}
	for _, char := range localPart {
		if char >= 'a' && char <= 'z' {
			continue
		}
		if char >= 'A' && char <= 'Z' {
			continue
		}
		if char >= '0' && char <= '9' {
			continue
		}
		if slices.Contains(allowedSpecialCharacters, char) {
			continue
		}
		return false
	}
	return true
}

func verifyEmailAddressDomainPart(domainPart string) bool {
	if len(domainPart) < 1 {
		return false
	}
	for _, char := range domainPart {
		if char >= 'a' && char <= 'z' {
			continue
		}
		if char >= 'A' && char <= 'Z' {
			continue
		}
		if char >= '0' && char <= '9' {
			continue
		}
		if char == '.' || char == '-' {
			continue
		}
		return false
	}
	return true
}
