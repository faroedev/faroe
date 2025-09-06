package faroe

import (
	"errors"
	"fmt"
	"time"
)

var userPasswordResetExpiration = 20 * time.Minute

type userPasswordResetStruct struct {
	id                               string
	userId                           string
	secretHash                       []byte
	temporaryPasswordHash            []byte
	temporaryPasswordHashAlgorithmId string
	temporaryPasswordSalt            []byte
	userFirstFactorVerified          bool
	newPasswordHash                  []byte
	newPasswordHashAlgorithmId       string
	newPasswordSalt                  []byte
	newPasswordSet                   bool
	userPasswordHashCounter          int32
	userEmailAddressCounter          int32
	userDisabledCounter              int32
	createdAt                        time.Time
}

func (server *ServerStruct) verifyUserPasswordResetExpiration(userPasswordReset userPasswordResetStruct) bool {
	now := server.clock.Now()
	return now.Sub(userPasswordReset.createdAt) < userPasswordResetExpiration
}

// Returns a user password resets, user password reset token, verification code, and error.
func (server *ServerStruct) createUserPasswordReset(userId string, userPasswordHashCounter int32, userEmailAddressCounter int32, userDisabledCounter int32) (userPasswordResetStruct, string, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)
	temporaryPassword := generateTemporaryPassword()
	temporaryPasswordHash, temporaryPasswordHashAlgorithmId, temporaryPasswordSalt, err := server.hashTemporaryPassword(temporaryPassword)
	if err != nil {
		return userPasswordResetStruct{}, "", "", fmt.Errorf("failed to hash verification code: %s", err.Error())
	}

	now := server.clock.Now()
	userPasswordReset := userPasswordResetStruct{
		id:                               id,
		userId:                           userId,
		secretHash:                       secretHash,
		temporaryPasswordHash:            temporaryPasswordHash,
		temporaryPasswordHashAlgorithmId: temporaryPasswordHashAlgorithmId,
		temporaryPasswordSalt:            temporaryPasswordSalt,
		userFirstFactorVerified:          false,
		newPasswordHash:                  nil,
		newPasswordHashAlgorithmId:       "",
		newPasswordSalt:                  nil,
		newPasswordSet:                   false,
		userPasswordHashCounter:          userPasswordHashCounter,
		userEmailAddressCounter:          userEmailAddressCounter,
		userDisabledCounter:              userDisabledCounter,
		createdAt:                        now,
	}
	token := createCredentialToken(id, secret)

	err = server.setUserPasswordResetInMainStorage(userPasswordReset)
	if err != nil {
		return userPasswordResetStruct{}, "", "", fmt.Errorf("failed to set user password reset in main storage: %s", err.Error())
	}

	return userPasswordReset, token, temporaryPassword, nil
}

func (server *ServerStruct) validateUserPasswordResetToken(userPasswordResetToken string) (userPasswordResetStruct, UserStruct, error) {
	userPasswordResetId, userPasswordResetSecret, err := parseCredentialToken(userPasswordResetToken)
	if err != nil {
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}

	userPasswordReset, user, err := server.getValidUserPasswordResetAndUser(userPasswordResetId)
	if err != nil && errors.Is(err, errUserPasswordResetNotFound) {
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}
	if err != nil {
		return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to get valid user password reset and user: %s", err.Error())
	}
	secretValid := verifyCredentialSecret(userPasswordReset.secretHash, userPasswordResetSecret)
	if !secretValid {
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}
	return userPasswordReset, user, nil
}

func (server *ServerStruct) getValidUserPasswordResetAndUser(userPasswordResetId string) (userPasswordResetStruct, UserStruct, error) {
	userPasswordReset, _, err := server.getUserPasswordResetFromMainStorage(userPasswordResetId)
	if err != nil && errors.Is(err, errUserPasswordResetNotFound) {
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}
	if err != nil {
		return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to get user password reset from main storage: %s", err.Error())
	}

	valid := server.verifyUserPasswordResetExpiration(userPasswordReset)
	if !valid {
		err = server.deleteUserPasswordResetFromMainStorage(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
		}
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}

	user, err := server.userStore.GetUser(userPasswordReset.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteUserPasswordResetFromMainStorage(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
		}
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}
	if err != nil {
		return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteUserPasswordResetFromMainStorage(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
		}
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}

	if userPasswordReset.userEmailAddressCounter != user.EmailAddressCounter {
		err = server.deleteUserPasswordResetFromMainStorage(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
		}
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}
	if userPasswordReset.userDisabledCounter != user.DisabledCounter {
		err = server.deleteUserPasswordResetFromMainStorage(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			return userPasswordResetStruct{}, UserStruct{}, fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
		}
		return userPasswordResetStruct{}, UserStruct{}, errUserPasswordResetNotFound
	}

	return userPasswordReset, user, nil
}

func (server *ServerStruct) deleteUserPasswordReset(userPasswordResetId string) error {
	err := server.deleteUserPasswordResetFromMainStorage(userPasswordResetId)
	if err != nil && errors.Is(err, errUserPasswordResetNotFound) {
		return errUserPasswordResetNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete user password reset from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordResetAsTemporaryPasswordVerified(userPasswordResetId string) error {
	userPasswordReset, counter, err := server.getUserPasswordResetFromMainStorage(userPasswordResetId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user password reset from main storage: %s", err.Error())
	}

	if userPasswordReset.userFirstFactorVerified {
		return errConflict
	}

	userPasswordReset.userFirstFactorVerified = true

	err = server.updateUserPasswordResetInMainStorage(userPasswordReset, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user password reset in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordResetNewPasswordHash(userPasswordResetId string, newPassword string) error {
	newPasswordHash, newPasswordHashAlgorithmId, newPasswordSalt, err := server.hashUserPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %s", err.Error())
	}

	userPasswordReset, counter, err := server.getUserPasswordResetFromMainStorage(userPasswordResetId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get user password reset from main storage: %s", err.Error())
	}

	if userPasswordReset.newPasswordSet {
		return errConflict
	}

	userPasswordReset.newPasswordHash = newPasswordHash
	userPasswordReset.newPasswordHashAlgorithmId = newPasswordHashAlgorithmId
	userPasswordReset.newPasswordSalt = newPasswordSalt
	userPasswordReset.newPasswordSet = true

	err = server.updateUserPasswordResetInMainStorage(userPasswordReset, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update user password reset in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setUserPasswordResetInMainStorage(userPasswordReset userPasswordResetStruct) error {
	encoded := encodeUserPasswordResetToBytes(userPasswordReset)
	expiresAt := userPasswordReset.createdAt.Add(userPasswordResetExpiration)

	err := server.mainStorage.Set(mainStorageKeyPrefixUserPasswordReset+userPasswordReset.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getUserPasswordResetFromMainStorage(userPasswordResetId string) (userPasswordResetStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixUserPasswordReset + userPasswordResetId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return userPasswordResetStruct{}, 0, errUserPasswordResetNotFound
	}
	if err != nil {
		return userPasswordResetStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeUserPasswordResetFromBytes(encoded)
	if err != nil {
		return userPasswordResetStruct{}, 0, fmt.Errorf("failed to decode user password reset bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteUserPasswordResetFromMainStorage(userPasswordResetId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixUserPasswordReset + userPasswordResetId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserPasswordResetNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateUserPasswordResetInMainStorage(userPasswordReset userPasswordResetStruct, storageEntryCounter int32) error {
	encoded := encodeUserPasswordResetToBytes(userPasswordReset)
	expiresAt := userPasswordReset.createdAt.Add(userPasswordResetExpiration)

	err := server.mainStorage.Update(mainStorageKeyPrefixUserPasswordReset+userPasswordReset.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errUserPasswordResetNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}

	return nil
}

func encodeUserPasswordResetToBytes(userPasswordReset userPasswordResetStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(userPasswordReset.id)
	binarySequence.addString(userPasswordReset.userId)
	binarySequence.add(userPasswordReset.secretHash)
	binarySequence.add(userPasswordReset.temporaryPasswordHash)
	binarySequence.addString(userPasswordReset.temporaryPasswordHashAlgorithmId)
	binarySequence.add(userPasswordReset.temporaryPasswordSalt)
	binarySequence.addBool(userPasswordReset.userFirstFactorVerified)
	binarySequence.add(userPasswordReset.newPasswordHash)
	binarySequence.addString(userPasswordReset.newPasswordHashAlgorithmId)
	binarySequence.add(userPasswordReset.newPasswordSalt)
	binarySequence.addBool(userPasswordReset.newPasswordSet)
	binarySequence.addInt32(userPasswordReset.userPasswordHashCounter)
	binarySequence.addInt32(userPasswordReset.userEmailAddressCounter)
	binarySequence.addInt32(userPasswordReset.userDisabledCounter)
	binarySequence.addInt64(userPasswordReset.createdAt.Unix())
	return binarySequence.encode()
}

func decodeUserPasswordResetFromBytes(encoded []byte) (userPasswordResetStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to parse binary sequence: %s", err.Error())
	}

	userPasswordReset, err := mapBinarySequenceToUserPasswordReset(binarySequence)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to map binary sequence to user password reset: %s", err.Error())
	}

	return userPasswordReset, nil
}

func mapBinarySequenceToUserPasswordReset(binarySequence binarySequenceType) (userPasswordResetStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get user id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(2)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	temporaryPasswordHash, err := binarySequence.get(3)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get temporary password hash: %s", err.Error())
	}
	temporaryPasswordHashAlgorithmId, err := binarySequence.getString(4)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get temporary password hash algorithm id: %s", err.Error())
	}
	temporaryPasswordSalt, err := binarySequence.get(5)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get temporary password salt: %s", err.Error())
	}
	userFirstFactorVerified, err := binarySequence.getBool(6)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get temporary password verified: %s", err.Error())
	}
	newPasswordHash, err := binarySequence.get(7)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get new password hash: %s", err.Error())
	}
	newPasswordHashAlgorithmId, err := binarySequence.getString(8)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get new password hash algorithm id: %s", err.Error())
	}
	newPasswordSalt, err := binarySequence.get(9)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get new password salt: %s", err.Error())
	}
	newPasswordSet, err := binarySequence.getBool(10)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get new password set flag: %s", err.Error())
	}
	userPasswordHashCounter, err := binarySequence.getInt32(11)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get new password counter: %s", err.Error())
	}
	userEmailAddressCounter, err := binarySequence.getInt32(12)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get user email address counter: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(13)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(14)
	if err != nil {
		return userPasswordResetStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	userPasswordReset := userPasswordResetStruct{
		id:                               id,
		userId:                           userId,
		secretHash:                       secretHash,
		temporaryPasswordHash:            temporaryPasswordHash,
		temporaryPasswordHashAlgorithmId: temporaryPasswordHashAlgorithmId,
		temporaryPasswordSalt:            temporaryPasswordSalt,
		userFirstFactorVerified:          userFirstFactorVerified,
		newPasswordHash:                  newPasswordHash,
		newPasswordHashAlgorithmId:       newPasswordHashAlgorithmId,
		newPasswordSalt:                  newPasswordSalt,
		newPasswordSet:                   newPasswordSet,
		userPasswordHashCounter:          userPasswordHashCounter,
		userEmailAddressCounter:          userEmailAddressCounter,
		userDisabledCounter:              userDisabledCounter,
		createdAt:                        time.Unix(createdAtUnix, 0),
	}

	return userPasswordReset, nil
}
