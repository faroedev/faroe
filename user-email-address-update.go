package faroe

import (
	"errors"
	"fmt"
	"time"
)

var userEmailAddressUpdateExpiration = 20 * time.Minute

type userEmailAddressUpdateStruct struct {
	id                           string
	userId                       string
	sessionId                    string
	secretHash                   []byte
	newEmailAddress              string
	emailAddressVerificationCode string
	newEmailAddressVerified      bool
	userIdentityVerified         bool
	userPasswordHashCounter      int32
	userEmailAddressCounter      int32
	userDisabledCounter          int32
	createdAt                    time.Time
}

func (server *ServerStruct) verifyUserEmailAddressUpdateExpiration(userEmailAddressUpdate userEmailAddressUpdateStruct) bool {
	now := server.clock.Now()
	return now.Sub(userEmailAddressUpdate.createdAt) <= userEmailAddressUpdateExpiration
}

func (server *ServerStruct) createUserEmailAddressUpdate(userId string, sessionId string, newEmailAddress string, userPasswordHashCounter int32, userEmailAddressCounter int32, userDisabledCounter int32) (userEmailAddressUpdateStruct, string, error) {
	id := generateRandomId()
	emailVerificationCode := generateVerificationCode()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)

	now := server.clock.Now()
	userEmailAddressUpdate := userEmailAddressUpdateStruct{
		id:                           id,
		userId:                       userId,
		sessionId:                    sessionId,
		secretHash:                   secretHash,
		newEmailAddress:              newEmailAddress,
		emailAddressVerificationCode: emailVerificationCode,
		newEmailAddressVerified:      false,
		userIdentityVerified:         false,
		userPasswordHashCounter:      userPasswordHashCounter,
		userEmailAddressCounter:      userEmailAddressCounter,
		userDisabledCounter:          userDisabledCounter,
		createdAt:                    now,
	}
	token := createCredentialToken(id, secret)

	err := server.setUserEmailAddressUpdateInMainStorage(userEmailAddressUpdate)
	if err != nil {
		return userEmailAddressUpdateStruct{}, "", fmt.Errorf("failed to set email address update in main storage: %s", err.Error())
	}
	return userEmailAddressUpdate, token, nil
}

func (server *ServerStruct) validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken string) (userEmailAddressUpdateStruct, UserStruct, error) {
	userEmailAddressUpdateId, userEmailAddressUpdateSecret, err := parseCredentialToken(userEmailAddressUpdateToken)
	if err != nil {
		return userEmailAddressUpdateStruct{}, UserStruct{}, errInvalidUserEmailAddressUpdateToken
	}

	userEmailAddressUpdate, user, err := server.getValidUserEmailAddressUpdateAndUser(userEmailAddressUpdateId)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return userEmailAddressUpdateStruct{}, UserStruct{}, errInvalidUserEmailAddressUpdateToken
	}
	if err != nil {
		return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get valid user email address update and user: %s", err.Error())
	}
	secretValid := verifyCredentialSecret(userEmailAddressUpdate.secretHash, userEmailAddressUpdateSecret)
	if !secretValid {
		return userEmailAddressUpdateStruct{}, UserStruct{}, errInvalidUserEmailAddressUpdateToken
	}

	return userEmailAddressUpdate, user, nil
}

func (server *ServerStruct) getValidUserEmailAddressUpdateAndUser(userEmailAddressUpdateId string) (userEmailAddressUpdateStruct, UserStruct, error) {
	userEmailAddressUpdate, _, err := server.getUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return userEmailAddressUpdateStruct{}, UserStruct{}, errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get email address update from main storage: %s", err.Error())
	}

	expirationValid := server.verifyUserEmailAddressUpdateExpiration(userEmailAddressUpdate)
	if !expirationValid {
		err = server.deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
			return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete email address update from main storage: %s", err.Error())
		}
		return userEmailAddressUpdateStruct{}, UserStruct{}, errUserEmailAddressUpdateNotFound
	}

	user, err := server.userStore.GetUser(userEmailAddressUpdate.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
			return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete email address update from main storage: %s", err.Error())
		}
		return userEmailAddressUpdateStruct{}, UserStruct{}, errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
			return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete email address update from main storage: %s", err.Error())
		}
		return userEmailAddressUpdateStruct{}, UserStruct{}, errUserEmailAddressUpdateNotFound
	}

	if userEmailAddressUpdate.userPasswordHashCounter != user.PasswordHashCounter || userEmailAddressUpdate.userEmailAddressCounter != user.EmailAddressCounter || userEmailAddressUpdate.userDisabledCounter != user.DisabledCounter {
		err = server.deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
			return userEmailAddressUpdateStruct{}, UserStruct{}, fmt.Errorf("failed to delete email address update from main storage: %s", err.Error())
		}
		return userEmailAddressUpdateStruct{}, UserStruct{}, errUserEmailAddressUpdateNotFound
	}

	return userEmailAddressUpdate, user, nil
}

func (server *ServerStruct) deleteUserEmailAddressUpdate(userEmailAddressUpdateId string) error {
	err := server.deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete user email address update from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserEmailAddressUpdateAsUserIdentityVerified(userEmailAddressUpdateId string) error {
	userEmailAddressUpdate, counter, err := server.getUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user email address update from main storage: %s", err.Error())
	}

	if userEmailAddressUpdate.userIdentityVerified {
		return errConflict
	}

	userEmailAddressUpdate.userIdentityVerified = true

	err = server.updateUserEmailAddressUpdateInMainStorage(userEmailAddressUpdate, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user email address update in mai storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserEmailAddressUpdateAsNewEmailAddressVerified(userEmailAddressUpdateId string) error {
	userEmailAddressUpdate, counter, err := server.getUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user email address update from main storage: %s", err.Error())
	}

	if userEmailAddressUpdate.newEmailAddressVerified {
		return errConflict
	}

	userEmailAddressUpdate.newEmailAddressVerified = true

	err = server.updateUserEmailAddressUpdateInMainStorage(userEmailAddressUpdate, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user email address update in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserEmailAddressUpdateInMainStorage(userEmailAddressUpdate userEmailAddressUpdateStruct) error {
	encoded := encodeUserEmailAddressUpdateToBytes(userEmailAddressUpdate)
	expiresAt := userEmailAddressUpdate.createdAt.Add(userEmailAddressUpdateExpiration)

	err := server.mainStorage.Set(mainStorageKeyPrefixUserEmailAddressUpdate+userEmailAddressUpdate.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId string) (userEmailAddressUpdateStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixUserEmailAddressUpdate + userEmailAddressUpdateId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return userEmailAddressUpdateStruct{}, 0, errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return userEmailAddressUpdateStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeUserEmailAddressUpdateFromBytes(encoded)
	if err != nil {
		return userEmailAddressUpdateStruct{}, 0, fmt.Errorf("failed to decode user email address update from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteUserEmailAddressUpdateFromMainStorage(userEmailAddressUpdateId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixUserEmailAddressUpdate + userEmailAddressUpdateId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}
	return nil
}

func (server *ServerStruct) updateUserEmailAddressUpdateInMainStorage(userEmailAddressUpdate userEmailAddressUpdateStruct, storageEntryCounter int32) error {
	encoded := encodeUserEmailAddressUpdateToBytes(userEmailAddressUpdate)
	expiresAt := userEmailAddressUpdate.createdAt.Add(userEmailAddressUpdateExpiration)

	err := server.mainStorage.Update(mainStorageKeyPrefixUserEmailAddressUpdate+userEmailAddressUpdate.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserEmailAddressUpdateNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}

	return nil
}

func encodeUserEmailAddressUpdateToBytes(userEmailAddressUpdate userEmailAddressUpdateStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(userEmailAddressUpdate.id)
	binarySequence.addString(userEmailAddressUpdate.userId)
	binarySequence.addString(userEmailAddressUpdate.sessionId)
	binarySequence.add(userEmailAddressUpdate.secretHash)
	binarySequence.addString(userEmailAddressUpdate.newEmailAddress)
	binarySequence.addString(userEmailAddressUpdate.emailAddressVerificationCode)
	binarySequence.addBool(userEmailAddressUpdate.newEmailAddressVerified)
	binarySequence.addBool(userEmailAddressUpdate.userIdentityVerified)
	binarySequence.addInt32(userEmailAddressUpdate.userPasswordHashCounter)
	binarySequence.addInt32(userEmailAddressUpdate.userEmailAddressCounter)
	binarySequence.addInt32(userEmailAddressUpdate.userDisabledCounter)
	binarySequence.addInt64(userEmailAddressUpdate.createdAt.Unix())
	return binarySequence.encode()
}

func decodeUserEmailAddressUpdateFromBytes(serialized []byte) (userEmailAddressUpdateStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(serialized)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to parse binary sequence from bytes: %s", err.Error())
	}

	userEmailAddressCounter, err := mapBinarySequenceToUserEmailAddress(binarySequence)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to map binary sequence to user email address: %s", err.Error())
	}
	return userEmailAddressCounter, nil
}

func mapBinarySequenceToUserEmailAddress(binarySequence binarySequenceType) (userEmailAddressUpdateStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get user id %s", err.Error())
	}
	sessionId, err := binarySequence.getString(2)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get session id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(3)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	newEmailAddress, err := binarySequence.getString(4)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get new email address: %s", err.Error())
	}
	emailAddressVerificationCode, err := binarySequence.getString(5)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get new email address verification code: %s", err.Error())
	}
	newEmailAddressVerified, err := binarySequence.getBool(6)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get new email address verified flag: %s", err.Error())
	}
	userIdentityVerified, err := binarySequence.getBool(7)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get user identity verified: %s", err.Error())
	}
	userPasswordHashCounter, err := binarySequence.getInt32(8)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get user password counter: %s", err.Error())
	}
	userEmailAddressCounter, err := binarySequence.getInt32(9)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get user email address counter: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(10)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(11)
	if err != nil {
		return userEmailAddressUpdateStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	userEmailAddressUpdate := userEmailAddressUpdateStruct{
		id:                           id,
		userId:                       userId,
		sessionId:                    sessionId,
		secretHash:                   secretHash,
		newEmailAddress:              newEmailAddress,
		emailAddressVerificationCode: emailAddressVerificationCode,
		newEmailAddressVerified:      newEmailAddressVerified,
		userIdentityVerified:         userIdentityVerified,
		userPasswordHashCounter:      userPasswordHashCounter,
		userEmailAddressCounter:      userEmailAddressCounter,
		userDisabledCounter:          userDisabledCounter,
		createdAt:                    time.Unix(createdAtUnix, 0),
	}

	return userEmailAddressUpdate, nil
}
