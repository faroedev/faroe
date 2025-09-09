package faroe

import (
	"errors"
	"time"
)

const (
	storageKeyPrefixSession                                                   = "aaah."
	storageKeyPrefixSignup                                                    = "aaai."
	storageKeyPrefixSignin                                                    = "aaaj."
	storageKeyPrefixUserEmailAddressUpdate                                    = "aaak."
	storageKeyPrefixUserPasswordUpdate                                        = "aaam."
	storageKeyPrefixUserPasswordReset                                         = "aaan."
	storageKeyPrefixUserDeletion                                              = "aaap."
	storageKeyPrefixVerifyUserPasswordTokenBucket                             = "aaaq."
	storageKeyPrefixSendEmailTokenBucket                                      = "aaar."
	storageKeyPrefixVerifyEmailAddressVerificationCodeEmailAddressTokenBucket = "aaas."
	storageKeyPrefixVerifyUserPasswordResetTemporaryPasswordUserTokenBucket   = "aaat."
)

// Keys have a maximum length of 255 bytes.
type StorageInterface interface {
	// Retrieves the value and counter associated with the given key
	// Returns [ErrStorageEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Get(key string) ([]byte, int32, error)

	// Stores the value under the given key.
	// The counter is set to 0.
	// expiresAt is just a soft expiration hint.
	// There is no requirement for the entry to be immediately deleted or considered invalid after expiration.
	// Returns [ErrStorageEntryAlreadyExists] if the key already exists.
	// An error is returned for any other failure.
	Add(key string, value []byte, expiresAt time.Time) error

	// Updates the value and TTL for the given key if the counter matches.
	// expiresAt is just a soft expiration hint.
	// There is no requirement for the entry to be immediately deleted or considered invalid after expiration.
	// Returns [ErrStorageEntryNotFound] if the key doesn't exist or the counter doesn't match.
	// An error is returned for any other failure.
	Update(key string, value []byte, expiresAt time.Time, counter int32) error

	// Removes the value associated with the given key.
	// Returns [ErrStorageEntryNotFound] if the key doesn't exist.
	// An error is returned for any other failure.
	Delete(key string) error
}

var ErrStorageEntryNotFound = errors.New("entry not found in storage")
var ErrStorageEntryAlreadyExists = errors.New("entry already exists in storage")
