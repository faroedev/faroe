package faroe

import (
	"errors"
	"fmt"
	"time"
)

var userDeletionExpiration = 10 * time.Minute

type userDeletionStruct struct {
	id                      string
	userId                  string
	sessionId               string
	secretHash              []byte
	userIdentityVerified    bool
	userPasswordHashCounter int32
	userDisabledCounter     int32
	createdAt               time.Time
}

func (server *ServerStruct) verifyUserDeletionExpiration(UserDeletion userDeletionStruct) bool {
	now := server.clock.Now()
	return now.Sub(UserDeletion.createdAt) <= userDeletionExpiration
}

func (server *ServerStruct) createUserDeletion(userId string, sessionId string, userPasswordHashCounter int32, userDisabledCounter int32) (userDeletionStruct, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)

	now := server.clock.Now()
	userDeletion := userDeletionStruct{
		id:                      id,
		userId:                  userId,
		sessionId:               sessionId,
		secretHash:              secretHash,
		userIdentityVerified:    false,
		userPasswordHashCounter: userPasswordHashCounter,
		userDisabledCounter:     userDisabledCounter,
		createdAt:               now,
	}
	token := createCredentialToken(id, secret)

	err := server.setUserDeletionInMainStorage(userDeletion)
	if err != nil {
		return userDeletionStruct{}, "", fmt.Errorf("failed to set user deletion in main storage: %s", err.Error())
	}

	return userDeletion, token, nil
}

func (server *ServerStruct) validateUserDeletionToken(userDeletionToken string) (userDeletionStruct, UserStruct, error) {
	userDeletionId, userDeletionSecret, err := parseCredentialToken(userDeletionToken)
	if err != nil {
		return userDeletionStruct{}, UserStruct{}, errInvalidUserDeletionToken
	}

	userDeletion, user, err := server.getValidUserDeletionAndUser(userDeletionId)
	if err != nil && errors.Is(err, errUserDeletionNotFound) {
		return userDeletionStruct{}, UserStruct{}, errInvalidUserDeletionToken
	}
	if err != nil {
		return userDeletionStruct{}, UserStruct{}, err
	}
	secretValid := verifyCredentialSecret(userDeletion.secretHash, userDeletionSecret)
	if !secretValid {
		return userDeletionStruct{}, UserStruct{}, errInvalidUserDeletionToken
	}

	return userDeletion, user, nil
}

func (server *ServerStruct) getValidUserDeletionAndUser(userDeletionId string) (userDeletionStruct, UserStruct, error) {
	userDeletion, _, err := server.getUserDeletionFromMainStorage(userDeletionId)
	if err != nil && errors.Is(err, errUserDeletionNotFound) {
		return userDeletionStruct{}, UserStruct{}, errUserDeletionNotFound
	}
	if err != nil {
		return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to get user deletion from main storage: %s", err.Error())
	}

	expirationValid := server.verifyUserDeletionExpiration(userDeletion)
	if !expirationValid {
		err = server.deleteUserDeletionFromMainStorage(userDeletion.id)
		if err != nil && errors.Is(err, errUserDeletionNotFound) {
			return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to delete user deletion from main storage: %s", err.Error())
		}
		return userDeletionStruct{}, UserStruct{}, errUserDeletionNotFound
	}

	user, err := server.userStore.GetUser(userDeletion.userId)
	if err != nil && errors.Is(err, ErrUserNotFound) {
		err = server.deleteUserDeletionFromMainStorage(userDeletion.id)
		if err != nil && errors.Is(err, errUserDeletionNotFound) {
			return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to delete user deletion from main storage: %s", err.Error())
		}
		return userDeletionStruct{}, UserStruct{}, errUserDeletionNotFound
	}
	if err != nil {
		return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteUserDeletionFromMainStorage(userDeletion.id)
		if err != nil && errors.Is(err, errUserDeletionNotFound) {
			return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to delete user deletion from main storage: %s", err.Error())
		}
		return userDeletionStruct{}, UserStruct{}, errUserDeletionNotFound
	}

	if userDeletion.userPasswordHashCounter != user.PasswordHashCounter || userDeletion.userDisabledCounter != user.DisabledCounter {
		err = server.deleteUserDeletionFromMainStorage(userDeletion.id)
		if err != nil && errors.Is(err, errUserDeletionNotFound) {
			return userDeletionStruct{}, UserStruct{}, fmt.Errorf("failed to delete user deletion from main storage: %s", err.Error())
		}
		return userDeletionStruct{}, UserStruct{}, errUserDeletionNotFound
	}

	return userDeletion, user, nil
}

func (server *ServerStruct) deleteUserDeletion(userDeletionId string) error {
	err := server.deleteUserDeletionFromMainStorage(userDeletionId)
	if err != nil && errors.Is(err, errUserDeletionNotFound) {
		return errUserDeletionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete user deletion from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserDeletionAsUserIdentityVerified(userDeletionId string) error {
	userDeletion, counter, err := server.getUserDeletionFromMainStorage(userDeletionId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user deletion from main storage: %s", err.Error())
	}

	if userDeletion.userIdentityVerified {
		return errConflict
	}

	userDeletion.userIdentityVerified = true

	err = server.updateUserDeletionInMainStorage(userDeletion, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user deletion in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserDeletionInMainStorage(userDeletion userDeletionStruct) error {
	encoded := encodeUserDeletionToBytes(userDeletion)
	expiresAt := userDeletion.createdAt.Add(userDeletionExpiration)

	err := server.mainStorage.Set(mainStorageKeyPrefixUserDeletion+userDeletion.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}
	return nil
}

func (server *ServerStruct) getUserDeletionFromMainStorage(userDeletionId string) (userDeletionStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixUserDeletion + userDeletionId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return userDeletionStruct{}, 0, errUserDeletionNotFound
	}
	if err != nil {
		return userDeletionStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeUserDeletionFromBytes(encoded)
	if err != nil {
		return userDeletionStruct{}, 0, fmt.Errorf("failed to decode user deletion from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteUserDeletionFromMainStorage(userDeletionId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixUserDeletion + userDeletionId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserDeletionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}
	return nil
}

func (server *ServerStruct) updateUserDeletionInMainStorage(userDeletion userDeletionStruct, storageEntryCounter int32) error {
	encoded := encodeUserDeletionToBytes(userDeletion)
	expiresAt := userDeletion.createdAt.Add(userDeletionExpiration)

	err := server.mainStorage.Update(mainStorageKeyPrefixUserDeletion+userDeletion.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserDeletionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}
	return nil
}

func encodeUserDeletionToBytes(userDeletion userDeletionStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(userDeletion.id)
	binarySequence.addString(userDeletion.userId)
	binarySequence.addString(userDeletion.sessionId)
	binarySequence.add(userDeletion.secretHash)
	binarySequence.addBool(userDeletion.userIdentityVerified)
	binarySequence.addInt32(userDeletion.userPasswordHashCounter)
	binarySequence.addInt32(userDeletion.userDisabledCounter)
	binarySequence.addInt64(userDeletion.createdAt.Unix())
	return binarySequence.encode()
}

func decodeUserDeletionFromBytes(encoded []byte) (userDeletionStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to parse binary sequence: %s", err.Error())
	}

	userDeletion, err := mapBinarySequenceToUserDeletion(binarySequence)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to map binary sequence to user deletion: %s", err.Error())
	}
	return userDeletion, nil
}

func mapBinarySequenceToUserDeletion(binarySequence binarySequenceType) (userDeletionStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get user id: %s", err.Error())
	}
	sessionId, err := binarySequence.getString(2)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get session id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(3)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	userIdentityVerified, err := binarySequence.getBool(4)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get user identity verified flag: %s", err.Error())
	}
	userPasswordHashCounter, err := binarySequence.getInt32(5)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get user password counter: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(6)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(7)
	if err != nil {
		return userDeletionStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	userDeletion := userDeletionStruct{
		id:                      id,
		userId:                  userId,
		sessionId:               sessionId,
		secretHash:              secretHash,
		userIdentityVerified:    userIdentityVerified,
		userPasswordHashCounter: userPasswordHashCounter,
		userDisabledCounter:     userDisabledCounter,
		createdAt:               time.Unix(createdAtUnix, 0),
	}

	return userDeletion, nil
}
