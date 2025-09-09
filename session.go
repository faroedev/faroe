package faroe

import (
	"errors"
	"fmt"
	"time"
)

type sessionStruct struct {
	id                  string
	userId              string
	secretHash          []byte
	tokenLastVerifiedAt time.Time
	userLastCheckedAt   time.Time
	userDisabledCounter int32
	userSessionsCounter int32
	createdAt           time.Time
}

type SessionConfigStruct struct {
	// A non-zero, positive value. Defines how long an inactive session remains valid.
	InactivityTimeout time.Duration

	// A non-zero, positive value. Defines how often session activity is recorded.
	ActivityCheckInterval time.Duration

	// Positive value. 0 if disabled
	Expiration time.Duration

	// Positive value. 0 if disabled
	UserCacheExpiration time.Duration
}

func (server *ServerStruct) verifySessionExpiration(session sessionStruct) bool {
	now := server.clock.Now()

	if server.sessionConfig.Expiration > 0 && now.Sub(session.createdAt) >= server.sessionConfig.Expiration {
		return false
	}
	if now.Sub(session.tokenLastVerifiedAt) >= server.sessionConfig.InactivityTimeout {
		return false
	}
	return true
}

func (server *ServerStruct) createSession(userId string, userDisabledCounter int32, userSessionsCounter int32) (sessionStruct, string, error) {
	id := generateRandomId()
	secret := generateSecret()
	secretHash := createCredentialSecretHash(secret)

	now := server.clock.Now()
	session := sessionStruct{
		id:                  id,
		userId:              userId,
		secretHash:          secretHash,
		tokenLastVerifiedAt: now,
		userDisabledCounter: userDisabledCounter,
		userSessionsCounter: userSessionsCounter,
		createdAt:           now,
	}
	token := createCredentialToken(id, secret)

	err := server.setSessionInStorage(session)
	if err != nil {
		return sessionStruct{}, "", fmt.Errorf("failed to set session in storage: %s", err.Error())
	}

	return session, token, nil
}

func (server *ServerStruct) validateSessionToken(sessionToken string) (sessionStruct, error) {
	sessionId, sessionSecret, err := parseCredentialToken(sessionToken)
	if err != nil {
		return sessionStruct{}, errInvalidSessionToken
	}

	session, err := server.getValidSession(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return sessionStruct{}, errInvalidSessionToken
	}
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get valid session: %s", err.Error())
	}

	secretValid := verifyCredentialSecret(session.secretHash, sessionSecret)
	if !secretValid {
		return sessionStruct{}, errInvalidSessionToken
	}

	now := server.clock.Now()
	if now.Sub(session.tokenLastVerifiedAt) >= server.sessionConfig.ActivityCheckInterval {
		err = server.updateSessionTokenLastVerifiedAt(session.id, now)
		if err != nil && !errors.Is(err, errConflict) {
			return sessionStruct{}, fmt.Errorf("failed to update session token last verified at: %s", err.Error())
		}
	}

	return session, nil
}

func (server *ServerStruct) validateSessionTokenAndUser(sessionToken string) (sessionStruct, UserStruct, error) {
	sessionId, sessionSecret, err := parseCredentialToken(sessionToken)
	if err != nil {
		return sessionStruct{}, UserStruct{}, errInvalidSessionToken
	}

	session, user, err := server.getValidSessionAndUser(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return sessionStruct{}, UserStruct{}, errInvalidSessionToken
	}
	if err != nil {
		return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to get valid session and user: %s", err.Error())
	}

	secretValid := verifyCredentialSecret(session.secretHash, sessionSecret)
	if !secretValid {
		return sessionStruct{}, UserStruct{}, errInvalidSessionToken
	}

	now := server.clock.Now()
	if now.Sub(session.tokenLastVerifiedAt) >= server.sessionConfig.ActivityCheckInterval {
		err = server.updateSessionTokenLastVerifiedAt(session.id, now)
		if err != nil && !errors.Is(err, errConflict) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to update session token last verified at: %s", err.Error())
		}
	}

	return session, user, nil
}

func (server *ServerStruct) getValidSessionAndUser(sessionId string) (sessionStruct, UserStruct, error) {
	session, _, err := server.getSessionFromStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to get session from storage: %s", err.Error())
	}

	expirationValid := server.verifySessionExpiration(session)
	if !expirationValid {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}

	user, err := server.userStore.GetUser(session.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}

	if session.userDisabledCounter != user.DisabledCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if session.userSessionsCounter != user.SessionsCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, UserStruct{}, errSessionNotFound
	}

	session = sessionStruct{
		id:                  session.id,
		userId:              session.userId,
		secretHash:          session.secretHash,
		tokenLastVerifiedAt: session.tokenLastVerifiedAt,
		createdAt:           session.createdAt,
	}

	return session, user, nil
}

func (server *ServerStruct) getValidSession(sessionId string) (sessionStruct, error) {
	session, counter, err := server.getSessionFromStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return sessionStruct{}, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get session from storage: %s", err.Error())
	}

	expirationValid := server.verifySessionExpiration(session)
	if !expirationValid {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, errSessionNotFound
	}

	if server.sessionConfig.UserCacheExpiration > 0 && server.clock.Now().Sub(session.userLastCheckedAt) < server.sessionConfig.UserCacheExpiration {
		return session, nil
	}

	session.userLastCheckedAt = server.clock.Now()

	user, err := server.userStore.GetUser(session.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, errSessionNotFound
	}

	if session.userDisabledCounter != user.DisabledCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, errSessionNotFound
	}
	if session.userSessionsCounter != user.SessionsCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return sessionStruct{}, errSessionNotFound
	}

	if server.sessionConfig.UserCacheExpiration > 0 {
		err = server.updateSessionInStorage(session, counter)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return sessionStruct{}, fmt.Errorf("failed to update session in storage: %s", err.Error())
		}
	}

	return session, nil
}

func (server *ServerStruct) deleteSession(sessionId string) error {
	err := server.deleteSessionFromStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete session from storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSessionTokenLastVerifiedAt(sessionId string, tokenLastVerifiedAt time.Time) error {
	session, storageEntryCounter, err := server.getSessionFromStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get session from storage: %s", err.Error())
	}

	if session.tokenLastVerifiedAt.After(tokenLastVerifiedAt) {
		return errConflict
	}

	session.tokenLastVerifiedAt = tokenLastVerifiedAt

	err = server.updateSessionInStorage(session, storageEntryCounter)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update session in storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSessionInStorage(session sessionStruct) error {
	encoded := encodeSessionToBytes(session)
	expiresAt := session.tokenLastVerifiedAt.Add(server.sessionConfig.InactivityTimeout)

	err := server.storage.Add(storageKeyPrefixSession+session.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) getSessionFromStorage(sessionId string) (sessionStruct, int32, error) {
	encoded, counter, err := server.storage.Get(storageKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return sessionStruct{}, 0, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, 0, fmt.Errorf("failed to get entry from storage: %s", err.Error())
	}

	decoded, err := decodeSessionFromBytes(encoded)
	if err != nil {
		return sessionStruct{}, 0, fmt.Errorf("failed to decode session from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) deleteSessionFromStorage(sessionId string) error {
	err := server.storage.Delete(storageKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSessionInStorage(session sessionStruct, storageEntryCounter int32) error {
	encoded := encodeSessionToBytes(session)
	expiresAt := session.tokenLastVerifiedAt.Add(server.sessionConfig.InactivityTimeout)

	err := server.storage.Update(storageKeyPrefixSession+session.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrStorageEntryNotFound) {
		return errSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in storage: %s", err.Error())
	}

	return nil
}

func encodeSessionToBytes(session sessionStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(session.id)
	binarySequence.addString(session.userId)
	binarySequence.add(session.secretHash)
	binarySequence.addInt64(session.tokenLastVerifiedAt.Unix())
	binarySequence.addInt64(session.userLastCheckedAt.Unix())
	binarySequence.addInt32(session.userDisabledCounter)
	binarySequence.addInt32(session.userSessionsCounter)
	binarySequence.addInt64(session.createdAt.Unix())
	return binarySequence.encode()
}

func decodeSessionFromBytes(encoded []byte) (sessionStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(encoded)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to parse binary sequence bytes: %s", err.Error())
	}

	session, err := mapBinarySequenceToSession(binarySequence)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to map binary sequence to session: %s", err.Error())
	}
	return session, nil
}

func mapBinarySequenceToSession(binarySequence binarySequenceType) (sessionStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(2)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	tokenLastVerifiedAtUnix, err := binarySequence.getInt64(3)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get token last verified at unix: %s", err.Error())
	}
	userLastCheckedAtUnix, err := binarySequence.getInt64(4)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user last check at unix: %s", err.Error())
	}
	userDisabledCounter, err := binarySequence.getInt32(5)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	userSessionsCounter, err := binarySequence.getInt32(6)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user sessions counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(7)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	session := sessionStruct{
		id:                  id,
		userId:              userId,
		secretHash:          secretHash,
		tokenLastVerifiedAt: time.Unix(tokenLastVerifiedAtUnix, 0),
		userLastCheckedAt:   time.Unix(userLastCheckedAtUnix, 0),
		userDisabledCounter: userDisabledCounter,
		userSessionsCounter: userSessionsCounter,
		createdAt:           time.Unix(createdAtUnix, 0),
	}

	return session, nil
}
