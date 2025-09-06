package faroe

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/faroedev/go-json"
)

const (
	userServerActionCreateUser                   = "create_user"
	userServerActionGetUser                      = "get_user"
	userServerActionGetUserByEmailAddress        = "get_user_by_email_address"
	userServerActionUpdateUserEmailAddress       = "update_user_email_address"
	userServerActionUpdateUserPasswordHash       = "update_user_password_hash"
	userServerActionIncrementUserSessionsCounter = "increment_user_sessions_counter"
	userServerActionDeleteUser                   = "delete_user"
)

// Use [NewUserServerClient].
// Implements [UserStoreInterface].
type UserServerClientStruct struct {
	actionInvocationEndpointClient ActionInvocationEndpointClientInterface
}

func NewUserServerClient(actionInvocationEndpointClient ActionInvocationEndpointClientInterface) *UserServerClientStruct {
	client := &UserServerClientStruct{actionInvocationEndpointClient: actionInvocationEndpointClient}
	return client
}

func (userServerClient *UserServerClientStruct) CreateUser(emailAddress string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte) (UserStruct, error) {
	encodedPasswordHash := base64.StdEncoding.EncodeToString(passwordHash)
	encodedPasswordSalt := base64.StdEncoding.EncodeToString(passwordSalt)

	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSONBuilder.AddString("password_hash", encodedPasswordHash)
	argumentsJSONBuilder.AddString("password_hash_algorithm_id", passwordHashAlgorithmId)
	argumentsJSONBuilder.AddString("password_salt", encodedPasswordSalt)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionCreateUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return UserStruct{}, ErrUserEmailAddressAlreadyUsed
			}
			return UserStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return UserStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (userServerClient *UserServerClientStruct) GetUser(userId string) (UserStruct, error) {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionGetUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return UserStruct{}, ErrUserNotFound
			}
			return UserStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return UserStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (userServerClient *UserServerClientStruct) GetUserByEmailAddress(emailAddress string) (UserStruct, error) {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, valuesJSONObject, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionGetUserByEmailAddress, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return UserStruct{}, fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return UserStruct{}, ErrUserNotFound
			}
			return UserStruct{}, fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return UserStruct{}, fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	userJSONObject, err := valuesJSONObject.GetJSONObject("user")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'user' field from values json object: %s", err.Error())
	}

	user, err := mapJSONObjectToUser(userJSONObject)
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to map json object to user: %s", err.Error())
	}

	return user, nil
}

func (userServerClient *UserServerClientStruct) UpdateUserEmailAddress(userId string, emailAddress string, userEmailAddressCounter int32) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddString("email_address", emailAddress)
	argumentsJSONBuilder.AddInt32("user_email_address_counter", userEmailAddressCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionUpdateUserEmailAddress, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return ErrUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return ErrUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (userServerClient *UserServerClientStruct) UpdateUserPasswordHash(userId string, passwordHash []byte, passwordHashAlgorithmId string, passwordSalt []byte, userPasswordHashCounter int32) error {
	encodedPasswordHash := base64.StdEncoding.EncodeToString(passwordHash)
	encodedPasswordSalt := base64.StdEncoding.EncodeToString(passwordSalt)

	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddString("password_hash", encodedPasswordHash)
	argumentsJSONBuilder.AddString("password_hash_algorithm_id", passwordHashAlgorithmId)
	argumentsJSONBuilder.AddString("password_salt", encodedPasswordSalt)
	argumentsJSONBuilder.AddInt32("user_password_hash_counter", userPasswordHashCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionUpdateUserPasswordHash, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return ErrUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return ErrUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (userServerClient *UserServerClientStruct) IncrementUserSessionsCounter(userId string, userSessionsCounter int32) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSONBuilder.AddInt32("user_sessions_counter", userSessionsCounter)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionIncrementUserSessionsCounter, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return ErrUserNotFound
			}
			if actionInvocationActionErr.errorCode == "email_address_already_used" {
				return ErrUserEmailAddressAlreadyUsed
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (userServerClient *UserServerClientStruct) DeleteUser(userId string) error {
	argumentsJSONBuilder := json.NewObjectBuilder()
	argumentsJSONBuilder.AddString("user_id", userId)
	argumentsJSON := argumentsJSONBuilder.Done()

	_, _, err := sendActionInvocationRequest(userServerClient.actionInvocationEndpointClient, userServerActionDeleteUser, argumentsJSON)
	if err != nil {
		if actionInvocationActionErr, ok := err.(*actionInvocationActionErrorStruct); ok {
			if actionInvocationActionErr.errorCode == "internal_error" {
				return fmt.Errorf("action invocation %s failed: internal error", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "internal_conflict" {
				return fmt.Errorf("action invocation %s failed: internal conflict", actionInvocationActionErr.actionInvocationId)
			}
			if actionInvocationActionErr.errorCode == "user_not_found" {
				return ErrUserNotFound
			}
			return fmt.Errorf("action invocation %s failed: unknown error code %s", actionInvocationActionErr.actionInvocationId, actionInvocationActionErr.errorCode)
		}
		return fmt.Errorf("failed to send action invocation request: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) checkEmailAddressAvailability(emailAddress string) (bool, error) {
	_, err := server.userStore.GetUserByEmailAddress(emailAddress)
	if err != nil && errors.Is(err, ErrUserNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	return false, nil
}

func mapJSONObjectToUser(userJSON json.ObjectStruct) (UserStruct, error) {
	userId, err := userJSON.GetString("id")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'id' field: %s", err.Error())
	}
	emailAddress, err := userJSON.GetString("email_address")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'email_address' field: %s", err.Error())
	}
	encodedPasswordHash, err := userJSON.GetString("password_hash")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'password_hash' field: %s", err.Error())
	}
	passwordHashAlgorithmId, err := userJSON.GetString("password_hash_algorithm_id")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'password_hash_algorithm_id' field: %s", err.Error())
	}
	encodedPasswordSalt, err := userJSON.GetString("password_salt")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'password_salt' field: %s", err.Error())
	}
	displayName, err := userJSON.GetString("display_name")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'display_name' field: %s", err.Error())
	}
	disabled, err := userJSON.GetBool("disabled")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'disabled' field: %s", err.Error())
	}
	emailAddressCounter, err := userJSON.GetInt32("email_address_counter")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'email_address_counter' field: %s", err.Error())
	}
	passwordHashCounter, err := userJSON.GetInt32("password_hash_counter")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'password_hash_counter' field: %s", err.Error())
	}
	disabledCounter, err := userJSON.GetInt32("disabled_counter")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'disabled_counter' field: %s", err.Error())
	}
	sessionsCounter, err := userJSON.GetInt32("sessions_counter")
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to read 'sessions_counter' field: %s", err.Error())
	}

	passwordHash, err := base64.StdEncoding.DecodeString(encodedPasswordHash)
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to decode password hash: %s", err.Error())
	}
	passwordSalt, err := base64.StdEncoding.DecodeString(encodedPasswordSalt)
	if err != nil {
		return UserStruct{}, fmt.Errorf("failed to decode password salt: %s", err.Error())
	}

	user := UserStruct{
		Id:                      userId,
		EmailAddress:            emailAddress,
		PasswordHash:            passwordHash,
		PasswordSalt:            passwordSalt,
		PasswordHashAlgorithmId: passwordHashAlgorithmId,
		DisplayName:             displayName,
		Disabled:                disabled,
		EmailAddressCounter:     emailAddressCounter,
		PasswordHashCounter:     passwordHashCounter,
		DisabledCounter:         disabledCounter,
		SessionsCounter:         sessionsCounter,
	}

	return user, nil
}
