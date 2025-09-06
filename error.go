package faroe

import (
	"errors"
)

var errSignupNotFound = errors.New("signup not found")
var errInvalidSignupToken = errors.New("invalid signup token")

var errSessionNotFound = errors.New("session not found")
var errInvalidSessionToken = errors.New("invalid session token")

var errUserPasswordResetNotFound = errors.New("user password reset not found")
var errInvalidUserPasswordResetToken = errors.New("invalid user password reset token")

var errUserEmailAddressUpdateNotFound = errors.New("user email update not found")
var errInvalidUserEmailAddressUpdateToken = errors.New("invalid email address update token")

var errUserPasswordUpdateNotFound = errors.New("user password update not found")
var errInvalidUserPasswordUpdateToken = errors.New("invalid user password update token")

var errUserDeletionNotFound = errors.New("user deletion not found")
var errInvalidUserDeletionToken = errors.New("invalid user deletion token")

var errSigninNotFound = errors.New("signin not found")
var errInvalidSigninToken = errors.New("invalid signin token")

var errConflict = errors.New("conflict")
