package faroe

import (
	"errors"
	"fmt"
	"time"
)

var signinExpiration = 10 * time.Minute

type signinStruct struct {
	id                      string
	userId                  string
	secretHash              []byte
	userFirstFactorVerified bool
	userPasswordHashCounter int32
	userDisabledCounter     int32
	createdAt               time.Time
}

func (server *ServerStruct) verifySigninExpiration(Signin signinStruct) bool {
	now := server.clock.Now()
	return now.Sub(Signin.createdAt) < signinExpiration
}

func (server *ServerStruct) createSignin(userId string, userPasswordHashCounter int32, userDisabledCounter int32) (signinStruct, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)

	now := server.clock.Now()
	signin := signinStruct{
		id:                      id,
		userId:                  userId,
		secretHash:              secretHash,
		userFirstFactorVerified: false,
		userPasswordHashCounter: userPasswordHashCounter,
		userDisabledCounter:     userDisabledCounter,
		createdAt:               now,
	}
	token := createCredentialToken(id, secret)

	err := server.setSigninInStorage(signin)
	if err != nil {
		return signinStruct{}, "", fmt.Errorf("failed to set signin in storage: %s", err.Error())
	}

	return signin, token, nil
}

func (server *ServerStruct) validateSigninToken(userPasswordResetToken string) (signinStruct, UserStruct, error) {
	signinId, signinSecret, err := parseCredentialToken(userPasswordResetToken)
	if err != nil {
		return signinStruct{}, UserStruct{}, errInvalidSigninToken
	}

	signin, user, err := server.getValidSigninAndUser(signinId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return signinStruct{}, UserStruct{}, errInvalidSigninToken
	}
	if err != nil {
		return signinStruct{}, UserStruct{}, fmt.Errorf("failed to valid signin and user: %s", err.Error())
	}
	secretValid := verifyCredentialSecret(signin.secretHash, signinSecret)
	if !secretValid {
		return signinStruct{}, UserStruct{}, errInvalidSigninToken
	}
	return signin, user, nil
}

func (server *ServerStruct) getValidSigninAndUser(signinId string) (signinStruct, UserStruct, error) {
	signin, _, err := server.getSigninFromStorage(signinId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}
	if err != nil {
		return signinStruct{}, UserStruct{}, fmt.Errorf("failed to get signin from storage: %s", err.Error())
	}

	valid := server.verifySigninExpiration(signin)
	if !valid {
		err = server.deleteSigninFromStorage(signin.id)
		if err != nil && !errors.Is(err, errSigninNotFound) {
			return signinStruct{}, UserStruct{}, fmt.Errorf("failed to delete signin from storage: %s", err.Error())
		}
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}

	user, err := server.userStore.GetUser(signin.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteSigninFromStorage(signin.id)
		if err != nil && !errors.Is(err, errSigninNotFound) {
			return signinStruct{}, UserStruct{}, fmt.Errorf("failed to delete signin from storage: %s", err.Error())
		}
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}
	if err != nil {
		return signinStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteSigninFromStorage(signin.id)
		if err != nil && !errors.Is(err, errSigninNotFound) {
			return signinStruct{}, UserStruct{}, fmt.Errorf("failed to delete signin from storage: %s", err.Error())
		}
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}

	if signin.userPasswordHashCounter != user.PasswordHashCounter {
		err = server.deleteSigninFromStorage(signin.id)
		if err != nil && !errors.Is(err, errSigninNotFound) {
			return signinStruct{}, UserStruct{}, fmt.Errorf("failed to delete signin from storage: %s", err.Error())
		}
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}
	if signin.userDisabledCounter != user.DisabledCounter {
		err = server.deleteSigninFromStorage(signin.id)
		if err != nil && !errors.Is(err, errSigninNotFound) {
			return signinStruct{}, UserStruct{}, fmt.Errorf("failed to delete signin from storage: %s", err.Error())
		}
		return signinStruct{}, UserStruct{}, errSigninNotFound
	}

	return signin, user, nil
}

func (server *ServerStruct) deleteSignin(signinId string) error {
	err := server.deleteSigninFromStorage(signinId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errSigninNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete signin from storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSigninAsUserFirstFactorVerified(signinId string) error {
	signin, counter, err := server.getSigninFromStorage(signinId)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get signin from storage: %s", err.Error())
	}

	if signin.userFirstFactorVerified {
		return errConflict
	}

	signin.userFirstFactorVerified = true

	err = server.updateSigninInStorage(signin, counter)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update signin in storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSigninInStorage(signin signinStruct) error {
	encoded := encodeSigninToBytes(signin)
	expiresAt := signin.createdAt.Add(signinExpiration)

	err := server.storage.Add(storageKeyPrefixSignin+signin.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getSigninFromStorage(signinId string) (signinStruct, int32, error) {
	encoded, counter, err := server.storage.Get(storageKeyPrefixSignin + signinId)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return signinStruct{}, 0, errSigninNotFound
	}
	if err != nil {
		return signinStruct{}, 0, fmt.Errorf("failed to get entry from storage: %s", err.Error())
	}

	decoded, err := decodeSigninFromBytes(encoded)
	if err != nil {
		return signinStruct{}, 0, fmt.Errorf("failed to decode signin from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteSigninFromStorage(signinId string) error {
	err := server.storage.Delete(storageKeyPrefixSignin + signinId)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return errSigninNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSigninInStorage(signin signinStruct, storageEntryCounter int32) error {
	encoded := encodeSigninToBytes(signin)
	expiresAt := signin.createdAt.Add(signinExpiration)

	err := server.storage.Update(storageKeyPrefixSignin+signin.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return errSigninNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in storage: %s", err.Error())
	}
	return nil
}

func encodeSigninToBytes(signin signinStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(signin.id)
	binarySequence.addString(signin.userId)
	binarySequence.add(signin.secretHash)
	binarySequence.addBool(signin.userFirstFactorVerified)
	binarySequence.addInt32(signin.userPasswordHashCounter)
	binarySequence.addInt32(signin.userDisabledCounter)
	binarySequence.addInt64(signin.createdAt.Unix())
	return binarySequence.encode()
}

func decodeSigninFromBytes(serialized []byte) (signinStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(serialized)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to parse binary sequence bytes: %s", err.Error())
	}

	signin, err := mapBinarySequenceToSignin(binarySequence)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to map binary sequence to signin: %s", err.Error())
	}
	return signin, nil
}

func mapBinarySequenceToSignin(binarySequence binarySequenceType) (signinStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get user id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(2)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	userFirstFactorVerified, err := binarySequence.getBool(3)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get user identity verified flag: %s", err.Error())
	}
	userPasswordHashCounter, err := binarySequence.getInt32(4)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get user password counter: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(5)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(6)
	if err != nil {
		return signinStruct{}, fmt.Errorf("failed to get user created at unix: %s", err.Error())
	}

	signin := signinStruct{
		id:                      id,
		userId:                  userId,
		secretHash:              secretHash,
		userFirstFactorVerified: userFirstFactorVerified,
		userPasswordHashCounter: userPasswordHashCounter,
		userDisabledCounter:     userDisabledCounter,
		createdAt:               time.Unix(createdAtUnix, 0),
	}

	return signin, nil
}
