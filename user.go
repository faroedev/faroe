package faroe

import "errors"

const (
	userServerActionCreateUser                   = "create_user"
	userServerActionGetUser                      = "get_user"
	userServerActionGetUserByEmailAddress        = "get_user_by_email_address"
	userServerActionUpdateUserEmailAddress       = "update_user_email_address"
	userServerActionUpdateUserPasswordHash       = "update_user_password_hash"
	userServerActionIncrementUserSessionsCounter = "increment_user_sessions_counter"
	userServerActionDeleteUser                   = "delete_user"
)

type UserStruct struct {
	// A unique ID.
	Id string

	// A unique email address.
	EmailAddress string

	PasswordHash []byte

	PasswordSalt []byte

	PasswordHashAlgorithmId string

	Disabled bool

	// An empty string if not defined.
	DisplayName string

	EmailAddressCounter int32

	PasswordHashCounter int32

	DisabledCounter int32

	SessionsCounter int32
}

type UserStoreInterface interface {
	// Creates a new user. The email address should be stored as-is, with the casing preserved.
	// The email address counter, password hash counter, disabled counter, and sessions counter should be set to 0.
	// Returns the created user if successful.
	// Returns [ErrUserEmailAddressAlreadyUsed] if the email address is already tied to another user.
	// An error is returned for any other failure.
	CreateUser(emailAddress string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte) (UserStruct, error)

	// Gets a user.
	// Returns [ErrUserNotFound] if a user doesn't exist.
	// An error is returned for any other failure.
	GetUser(userId string) (UserStruct, error)

	// Gets a user by email address.
	// The email address must match exactly, including letter casing.
	// Returns [ErrUserNotFound] if a user doesn't exist.
	// An error is returned for any other failure.
	GetUserByEmailAddress(emailAddress string) (UserStruct, error)

	// Updates a user's email address and increment a user's email address counter if the email address counter matches.
	// The new email address should be stored as-is, with the casing preserved.
	// Returns [ErrUserNotFound] if a user doesn't exist or the user's email address counter doesn't match.
	// Returns [ErrUserEmailAddressAlreadyUsed] if the email address is already tied to another user.
	// An error is returned for any other failure.
	UpdateUserEmailAddress(userId string, emailAddress string, userEmailAddressCounter int32) error

	// Updates a user's password hash, password hash algorithm ID, and password salt,
	// as well as increment a user's email address counter, if the user password hash counter matches.
	// Returns [ErrUserNotFound] if a user doesn't exist or the user's password hash counter doesn't match.
	// An error is returned for any other failure.
	UpdateUserPasswordHash(userId string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte, userPasswordHashCounter int32) error

	// Increments a user's sessions counter if the user's sessions counter matches.
	// Returns [ErrUserNotFound] if a user doesn't exist or the user's sessions counter doesn't match.
	// An error is returned for any other failure.
	IncrementUserSessionsCounter(userId string, userSessionsCounter int32) error

	// Deletes a user.
	// Returns [ErrUserNotFound] if a user doesn't exist.
	// An error is returned for any other failure.
	DeleteUser(userId string) error
}

var ErrUserNotFound = errors.New("user not found")
var ErrUserEmailAddressAlreadyUsed = errors.New("user email address already used")
