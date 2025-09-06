package faroe

import (
	"errors"
	"fmt"
	"time"
)

var userPasswordUpdateExpiration = 10 * time.Minute

type userPasswordUpdateStruct struct {
	id                         string
	userId                     string
	sessionId                  string
	secretHash                 []byte
	newPasswordHash            []byte
	newPasswordHashAlgorithmId string
	newPasswordSalt            []byte
	newPasswordSet             bool
	userIdentityVerified       bool
	userPasswordHashCounter    int32
	userDisabledCounter        int32
	createdAt                  time.Time
}

func (server *ServerStruct) verifyUserPasswordUpdateExpiration(userPasswordUpdate userPasswordUpdateStruct) bool {
	now := server.clock.Now()
	return now.Sub(userPasswordUpdate.createdAt) <= userPasswordUpdateExpiration
}

func (server *ServerStruct) createUserPasswordUpdate(userId string, sessionId string, userPasswordHashCounter int32, userDisabledCounter int32) (userPasswordUpdateStruct, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)

	now := server.clock.Now()
	userPasswordUpdate := userPasswordUpdateStruct{
		id:                         id,
		userId:                     userId,
		sessionId:                  sessionId,
		secretHash:                 secretHash,
		newPasswordHash:            nil,
		newPasswordHashAlgorithmId: "",
		newPasswordSalt:            nil,
		newPasswordSet:             false,
		userIdentityVerified:       false,
		userPasswordHashCounter:    userPasswordHashCounter,
		userDisabledCounter:        userDisabledCounter,
		createdAt:                  now,
	}
	token := createCredentialToken(id, secret)

	err := server.setUserPasswordUpdateInMainStorage(userPasswordUpdate)
	if err != nil {
		return userPasswordUpdateStruct{}, "", fmt.Errorf("failed to set user password update in main storage: %s", err.Error())
	}

	return userPasswordUpdate, token, nil
}

func (server *ServerStruct) validateUserPasswordUpdateToken(userPasswordUpdateToken string) (userPasswordUpdateStruct, UserStruct, error) {
	userPasswordUpdateId, userPasswordUpdateSecret, err := parseCredentialToken(userPasswordUpdateToken)
	if err != nil {
		return userPasswordUpdateStruct{}, UserStruct{}, errInvalidUserPasswordUpdateToken
	}

	userPasswordUpdate, user, err := server.getValidUserPasswordUpdateAndUser(userPasswordUpdateId)
	if err != nil && errors.Is(err, errUserPasswordUpdateNotFound) {
		return userPasswordUpdateStruct{}, UserStruct{}, errInvalidUserPasswordUpdateToken
	}
	if err != nil {
		return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get valid user user password update and user: %s", err.Error())
	}
	secretValid := verifyCredentialSecret(userPasswordUpdate.secretHash, userPasswordUpdateSecret)
	if !secretValid {
		return userPasswordUpdateStruct{}, UserStruct{}, errInvalidUserPasswordUpdateToken
	}

	return userPasswordUpdate, user, nil
}

func (server *ServerStruct) getValidUserPasswordUpdateAndUser(userPasswordUpdateId string) (userPasswordUpdateStruct, UserStruct, error) {
	userPasswordUpdate, _, err := server.getUserPasswordUpdateFromMainStorage(userPasswordUpdateId)
	if err != nil && errors.Is(err, errUserPasswordUpdateNotFound) {
		return userPasswordUpdateStruct{}, UserStruct{}, errUserPasswordUpdateNotFound
	}
	if err != nil {
		return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get password user update from main storage: %s", err.Error())
	}

	expirationValid := server.verifyUserPasswordUpdateExpiration(userPasswordUpdate)
	if !expirationValid {
		err = server.deleteUserPasswordUpdateFromMainStorage(userPasswordUpdate.id)
		if err != nil && !errors.Is(err, errUserPasswordUpdateNotFound) {
			return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password update from main storage: %s", err.Error())
		}
		return userPasswordUpdateStruct{}, UserStruct{}, errUserPasswordUpdateNotFound
	}

	user, err := server.userStore.GetUser(userPasswordUpdate.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteUserPasswordUpdateFromMainStorage(userPasswordUpdate.id)
		if err != nil && !errors.Is(err, errUserPasswordUpdateNotFound) {
			return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password update from main storage: %s", err.Error())
		}
		return userPasswordUpdateStruct{}, UserStruct{}, errUserPasswordUpdateNotFound
	}
	if err != nil {
		return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteUserPasswordUpdateFromMainStorage(userPasswordUpdate.id)
		if err != nil && !errors.Is(err, errUserPasswordUpdateNotFound) {
			return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password update from main storage: %s", err.Error())
		}
		return userPasswordUpdateStruct{}, UserStruct{}, errUserPasswordUpdateNotFound
	}

	if userPasswordUpdate.userPasswordHashCounter != user.PasswordHashCounter || userPasswordUpdate.userDisabledCounter != user.DisabledCounter {
		err = server.deleteUserPasswordUpdateFromMainStorage(userPasswordUpdate.id)
		if err != nil && !errors.Is(err, errUserPasswordUpdateNotFound) {
			return userPasswordUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password update from main storage: %s", err.Error())
		}
		return userPasswordUpdateStruct{}, UserStruct{}, errUserPasswordUpdateNotFound
	}

	return userPasswordUpdate, user, nil
}

func (server *ServerStruct) deleteUserPasswordUpdate(userPasswordUpdateId string) error {
	err := server.deleteUserPasswordUpdateFromMainStorage(userPasswordUpdateId)
	if err != nil && errors.Is(err, errUserPasswordUpdateNotFound) {
		return errUserPasswordUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete user password update from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordUpdateAsUserIdentityVerified(userPasswordUpdateId string) error {
	userPasswordUpdate, counter, err := server.getUserPasswordUpdateFromMainStorage(userPasswordUpdateId)
	if err != nil && errors.Is(err, errUserPasswordUpdateNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user email address update from main storage: %s", err.Error())
	}

	if userPasswordUpdate.userIdentityVerified {
		return errConflict
	}

	userPasswordUpdate.userIdentityVerified = true

	err = server.updateUserPasswordUpdateInMainStorage(userPasswordUpdate, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user email address update in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordUpdateNewPasswordHash(userPasswordUpdateId string, newPassword string) error {
	newPasswordHash, newPasswordHashAlgorithmId, newPasswordSalt, err := server.hashUserPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %s", err.Error())
	}

	userPasswordUpdate, counter, err := server.getUserPasswordUpdateFromMainStorage(userPasswordUpdateId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user password update from main storage: %s", err.Error())
	}

	if userPasswordUpdate.newPasswordSet {
		return errConflict
	}

	userPasswordUpdate.newPasswordHash = newPasswordHash
	userPasswordUpdate.newPasswordHashAlgorithmId = newPasswordHashAlgorithmId
	userPasswordUpdate.newPasswordSalt = newPasswordSalt
	userPasswordUpdate.newPasswordSet = true

	err = server.updateUserPasswordUpdateInMainStorage(userPasswordUpdate, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user password update in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordUpdateInMainStorage(userPasswordUpdate userPasswordUpdateStruct) error {
	encoded := encodeUserPasswordUpdateToBytes(userPasswordUpdate)
	expiresAt := userPasswordUpdate.createdAt.Add(userPasswordUpdateExpiration)

	err := server.mainStorage.Set(mainStorageKeyPrefixUserPasswordUpdate+userPasswordUpdate.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getUserPasswordUpdateFromMainStorage(userPasswordUpdateId string) (userPasswordUpdateStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixUserPasswordUpdate + userPasswordUpdateId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return userPasswordUpdateStruct{}, 0, errUserPasswordUpdateNotFound
	}
	if err != nil {
		return userPasswordUpdateStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeUserPasswordUpdateFromBytes(encoded)
	if err != nil {
		return userPasswordUpdateStruct{}, 0, fmt.Errorf("failed to decode user password update from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteUserPasswordUpdateFromMainStorage(userPasswordUpdateId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixUserPasswordUpdate + userPasswordUpdateId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserPasswordUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateUserPasswordUpdateInMainStorage(userPasswordUpdate userPasswordUpdateStruct, storageEntryCounter int32) error {
	encoded := encodeUserPasswordUpdateToBytes(userPasswordUpdate)
	expiresAt := userPasswordUpdate.createdAt.Add(userPasswordUpdateExpiration)

	err := server.mainStorage.Update(mainStorageKeyPrefixUserPasswordUpdate+userPasswordUpdate.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserPasswordUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}

	return nil
}

func encodeUserPasswordUpdateToBytes(userPasswordUpdate userPasswordUpdateStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(userPasswordUpdate.id)
	binarySequence.addString(userPasswordUpdate.userId)
	binarySequence.addString(userPasswordUpdate.sessionId)
	binarySequence.add(userPasswordUpdate.secretHash)
	binarySequence.addBool(userPasswordUpdate.userIdentityVerified)
	binarySequence.add(userPasswordUpdate.newPasswordHash)
	binarySequence.addString(userPasswordUpdate.newPasswordHashAlgorithmId)
	binarySequence.add(userPasswordUpdate.newPasswordSalt)
	binarySequence.addBool(userPasswordUpdate.newPasswordSet)
	binarySequence.addInt32(userPasswordUpdate.userPasswordHashCounter)
	binarySequence.addInt32(userPasswordUpdate.userDisabledCounter)
	binarySequence.addInt64(userPasswordUpdate.createdAt.Unix())
	return binarySequence.encode()
}

func decodeUserPasswordUpdateFromBytes(encoded []byte) (userPasswordUpdateStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to parse binary sequence: %s", err.Error())
	}

	userPasswordUpdate, err := mapBinarySequenceToUserPasswordUpdate(binarySequence)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to map binary sequence to user password update: %s", err.Error())
	}

	return userPasswordUpdate, nil
}

func mapBinarySequenceToUserPasswordUpdate(binarySequence binarySequenceType) (userPasswordUpdateStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get user id %s", err.Error())
	}
	sessionId, err := binarySequence.getString(2)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get session id %s", err.Error())
	}
	secretHash, err := binarySequence.get(3)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	userIdentityVerified, err := binarySequence.getBool(4)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get user first user identity verified flag: %s", err.Error())
	}
	newPasswordHash, err := binarySequence.get(5)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get new password hash: %s", err.Error())
	}
	newPasswordHashAlgorithmId, err := binarySequence.getString(6)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get new password hash algorithm id: %s", err.Error())
	}
	newPasswordSalt, err := binarySequence.get(7)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get new password salt: %s", err.Error())
	}
	newPasswordSet, err := binarySequence.getBool(8)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get new password set flag: %s", err.Error())
	}
	userPasswordHashCounter, err := binarySequence.getInt32(9)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get user password counter: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(10)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(11)
	if err != nil {
		return userPasswordUpdateStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	userPasswordUpdate := userPasswordUpdateStruct{
		id:                         id,
		userId:                     userId,
		sessionId:                  sessionId,
		secretHash:                 secretHash,
		userIdentityVerified:       userIdentityVerified,
		newPasswordHash:            newPasswordHash,
		newPasswordHashAlgorithmId: newPasswordHashAlgorithmId,
		newPasswordSalt:            newPasswordSalt,
		newPasswordSet:             newPasswordSet,
		userPasswordHashCounter:    userPasswordHashCounter,
		userDisabledCounter:        userDisabledCounter,
		createdAt:                  time.Unix(createdAtUnix, 0),
	}

	return userPasswordUpdate, nil
}
