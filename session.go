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
	userDisabledCounter int32
	userSessionsCounter int32
	createdAt           time.Time
}

type cachedSessionStruct struct {
	id                  string
	userId              string
	secretHash          []byte
	tokenLastVerifiedAt time.Time
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
	CacheExpiration time.Duration
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

func (server *ServerStruct) verifyCachedSessionExpiration(session cachedSessionStruct) bool {
	now := server.clock.Now()

	if server.sessionConfig.Expiration > 0 && now.Sub(session.createdAt) >= server.sessionConfig.Expiration {
		return false
	}
	if now.Sub(session.tokenLastVerifiedAt) >= server.sessionConfig.InactivityTimeout {
		return false
	}
	return true
}

func (server *ServerStruct) createSession(userId string, userDisabledCounter int32, userSessionsCounter int32) (cachedSessionStruct, string, error) {
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

	cachedSession, err := server.setSessionInStorage(session)
	if err != nil {
		return cachedSessionStruct{}, "", fmt.Errorf("failed to set session in storage: %s", err.Error())
	}

	return cachedSession, token, nil
}

func (server *ServerStruct) validateSessionToken(sessionToken string) (cachedSessionStruct, error) {
	sessionId, sessionSecret, err := parseCredentialToken(sessionToken)
	if err != nil {
		return cachedSessionStruct{}, errInvalidSessionToken
	}

	cachedSession, err := server.getValidSession(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, errInvalidSessionToken
	}
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get valid session: %s", err.Error())
	}

	secretValid := verifyCredentialSecret(cachedSession.secretHash, sessionSecret)
	if !secretValid {
		return cachedSessionStruct{}, errInvalidSessionToken
	}

	now := server.clock.Now()
	if now.Sub(cachedSession.tokenLastVerifiedAt) >= server.sessionConfig.ActivityCheckInterval {
		err = server.updateSessionTokenLastVerifiedAt(cachedSession.id, now)
		if err == nil {
			cachedSession.tokenLastVerifiedAt = now

			err = server.deleteSessionFromCache(sessionId)
			if err != nil {
				return cachedSessionStruct{}, fmt.Errorf("failed to delete session from cache: %s", err.Error())
			}
		} else if !errors.Is(err, errConflict) {
			return cachedSessionStruct{}, fmt.Errorf("failed to update session token last verified at: %s", err.Error())
		}
	}

	return cachedSession, nil
}

func (server *ServerStruct) validateSessionTokenAndUser(sessionToken string) (cachedSessionStruct, UserStruct, error) {
	sessionId, sessionSecret, err := parseCredentialToken(sessionToken)
	if err != nil {
		return cachedSessionStruct{}, UserStruct{}, errInvalidSessionToken
	}

	cachedSession, user, err := server.getValidSessionAndUser(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, UserStruct{}, errInvalidSessionToken
	}
	if err != nil {
		return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to get valid session and user: %s", err.Error())
	}

	secretValid := verifyCredentialSecret(cachedSession.secretHash, sessionSecret)
	if !secretValid {
		return cachedSessionStruct{}, UserStruct{}, errInvalidSessionToken
	}

	now := server.clock.Now()
	if now.Sub(cachedSession.tokenLastVerifiedAt) >= server.sessionConfig.ActivityCheckInterval {
		err = server.updateSessionTokenLastVerifiedAt(cachedSession.id, now)
		if err != nil && !errors.Is(err, errConflict) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to update session token last verified at: %s", err.Error())
		}
	}

	return cachedSession, user, nil
}

func (server *ServerStruct) getValidSessionAndUser(sessionId string) (cachedSessionStruct, UserStruct, error) {
	cachedSession, err := server.getSessionFromCache(sessionId)
	if err == nil {
		expirationValid := server.verifyCachedSessionExpiration(cachedSession)
		if expirationValid {
			user, err := server.userStore.GetUser(cachedSession.userId)
			if err != nil && errors.Is(err, ErrUserNotFound) {
				err = server.deleteSessionFromCache(cachedSession.id)
				if err != nil {
					return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from cache: %s", err.Error())
				}
				return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
			}
			if err != nil {
				return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
			}
			if user.Disabled {
				err = server.deleteSessionFromCache(cachedSession.id)
				if err != nil {
					return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from cache: %s", err.Error())
				}
				return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
			}

			return cachedSession, user, nil
		}

		err = server.deleteSessionFromCache(cachedSession.id)
		if err != nil {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from cache: %s", err.Error())
		}
	}
	if !errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to get session from cache: %s", err.Error())
	}

	session, _, err := server.getSessionFromMainStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if err != nil {
		return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to get session from main storage: %s", err.Error())
	}

	expirationValid := server.verifySessionExpiration(session)
	if !expirationValid {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}

	user, err := server.userStore.GetUser(session.userId)
	if err != nil && errors.Is(err, ErrUserNotFound) {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if err != nil {
		return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}

	if session.userDisabledCounter != user.DisabledCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}
	if session.userSessionsCounter != user.SessionsCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, UserStruct{}, errSessionNotFound
	}

	cachedSession = cachedSessionStruct{
		id:                  session.id,
		userId:              session.userId,
		secretHash:          session.secretHash,
		tokenLastVerifiedAt: session.tokenLastVerifiedAt,
		createdAt:           session.createdAt,
	}

	err = server.setSessionInCache(cachedSession)
	if err != nil {
		return cachedSessionStruct{}, UserStruct{}, fmt.Errorf("failed to set session in cache: %s", err.Error())
	}

	return cachedSession, user, nil
}

func (server *ServerStruct) getValidSession(sessionId string) (cachedSessionStruct, error) {
	cachedSession, err := server.getSessionFromCache(sessionId)
	if err == nil {
		expirationValid := server.verifyCachedSessionExpiration(cachedSession)
		if expirationValid {
			return cachedSession, nil
		}

		err = server.deleteSessionFromCache(cachedSession.id)
		if err != nil {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from cache: %s", err.Error())
		}
	} else if !errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, fmt.Errorf("failed to get cached session: %s", err.Error())
	}

	session, _, err := server.getSessionFromMainStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return cachedSessionStruct{}, errSessionNotFound
	}
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get session from main storage: %s", err.Error())
	}

	expirationValid := server.verifySessionExpiration(session)
	if !expirationValid {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, errSessionNotFound
	}

	user, err := server.userStore.GetUser(session.userId)
	if err != nil && errors.Is(err, ErrUserNotFound) {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, errSessionNotFound
	}
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get user from user api: %s", err.Error())
	}
	if user.Disabled {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, errSessionNotFound
	}

	if session.userDisabledCounter != user.DisabledCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, errSessionNotFound
	}
	if session.userSessionsCounter != user.SessionsCounter {
		err = server.deleteSessionFromStorage(session.id)
		if err != nil && !errors.Is(err, errSessionNotFound) {
			return cachedSessionStruct{}, fmt.Errorf("failed to delete session from storage: %s", err.Error())
		}
		return cachedSessionStruct{}, errSessionNotFound
	}

	cachedSession = cachedSessionStruct{
		id:                  session.id,
		userId:              session.userId,
		secretHash:          session.secretHash,
		tokenLastVerifiedAt: session.tokenLastVerifiedAt,
		createdAt:           session.createdAt,
	}

	err = server.setSessionInCache(cachedSession)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to set session in cache: %s", err.Error())
	}

	return cachedSession, nil
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
	session, storageEntryCounter, err := server.getSessionFromMainStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errConflict
	}
	if err != nil {
		return fmt.Errorf("failed to get session from main storage: %s", err.Error())
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

func (server *ServerStruct) setSessionInStorage(session sessionStruct) (cachedSessionStruct, error) {
	err := server.setSessionInMainStorage(session)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to set session in main storage %s", err.Error())
	}

	cachedSession := cachedSessionStruct{
		id:                  session.id,
		userId:              session.userId,
		secretHash:          session.secretHash,
		tokenLastVerifiedAt: session.tokenLastVerifiedAt,
		createdAt:           session.createdAt,
	}

	err = server.setSessionInCache(cachedSession)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to set session in cache: %s", err.Error())
	}

	return cachedSession, nil
}

func (server *ServerStruct) setSessionInMainStorage(session sessionStruct) error {
	encoded := encodeSessionToBytes(session)
	expiresAt := session.tokenLastVerifiedAt.Add(server.sessionConfig.InactivityTimeout)

	err := server.mainStorage.Set(mainStorageKeyPrefixSession+session.id, encoded, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set entry in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) setSessionInCache(session cachedSessionStruct) error {
	if server.sessionConfig.CacheExpiration > 0 {
		encoded := encodeCachedSessionToBytes(session)

		err := server.cache.Set(cacheKeyPrefixSession+session.id, encoded, server.sessionConfig.CacheExpiration)
		if err != nil {
			return fmt.Errorf("failed to set entry in cache: %s", err.Error())
		}
	}

	return nil
}

func (server *ServerStruct) getSessionFromMainStorage(sessionId string) (sessionStruct, int32, error) {
	encoded, counter, err := server.mainStorage.Get(mainStorageKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return sessionStruct{}, 0, errSessionNotFound
	}
	if err != nil {
		return sessionStruct{}, 0, fmt.Errorf("failed to get entry from main storage: %s", err.Error())
	}

	decoded, err := decodeSessionFromBytes(encoded)
	if err != nil {
		return sessionStruct{}, 0, fmt.Errorf("failed to decode session from bytes: %s", err.Error())
	}

	return decoded, counter, nil
}

func (server *ServerStruct) getSessionFromCache(sessionId string) (cachedSessionStruct, error) {
	encoded, err := server.cache.Get(cacheKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrCacheEntryNotFound) {
		return cachedSessionStruct{}, errSessionNotFound
	}
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get entry from cache: %s", err.Error())
	}

	decoded, err := decodeCachedSessionFromBytes(encoded)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to decode session from bytes: %s", err.Error())
	}

	return decoded, nil
}

func (server *ServerStruct) deleteSessionFromStorage(sessionId string) error {
	err := server.deleteSessionFromMainStorage(sessionId)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete session from main storage: %s", err.Error())
	}

	err = server.deleteSessionFromCache(sessionId)
	if err != nil {
		return fmt.Errorf("failed to delete session from cache: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) deleteSessionFromMainStorage(sessionId string) error {
	err := server.mainStorage.Delete(mainStorageKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) deleteSessionFromCache(sessionId string) error {
	err := server.cache.Delete(cacheKeyPrefixSession + sessionId)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete entry from cache: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSessionInStorage(session sessionStruct, storageEntryCounter int32) error {
	err := server.updateSessionInMainStorage(session, storageEntryCounter)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return errSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update session in main storage: %s", err.Error())
	}

	return nil
}

func (server *ServerStruct) updateSessionInMainStorage(session sessionStruct, storageEntryCounter int32) error {
	encoded := encodeSessionToBytes(session)
	expiresAt := session.tokenLastVerifiedAt.Add(server.sessionConfig.InactivityTimeout)

	err := server.mainStorage.Update(mainStorageKeyPrefixSession+session.id, encoded, expiresAt, storageEntryCounter)
	if err != nil && errors.Is(err, ErrMainStorageEntryNotFound) {
		return errSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to update entry in main storage: %s", err.Error())
	}

	return nil
}

func encodeSessionToBytes(session sessionStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(session.id)
	binarySequence.addString(session.userId)
	binarySequence.add(session.secretHash)
	binarySequence.addInt64(session.tokenLastVerifiedAt.Unix())
	binarySequence.addInt32(session.userDisabledCounter)
	binarySequence.addInt32(session.userSessionsCounter)
	binarySequence.addInt64(session.createdAt.Unix())
	return binarySequence.encode()
}

func encodeCachedSessionToBytes(session cachedSessionStruct) []byte {
	binarySequence := binarySequenceType{}
	binarySequence.addString(session.id)
	binarySequence.addString(session.userId)
	binarySequence.add(session.secretHash)
	binarySequence.addInt64(session.tokenLastVerifiedAt.Unix())
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
	userDisabledCounter, err := binarySequence.getInt32(4)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user disabled counter: %s", err.Error())
	}
	userSessionsCounter, err := binarySequence.getInt32(5)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get user sessions counter: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(6)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	session := sessionStruct{
		id:                  id,
		userId:              userId,
		secretHash:          secretHash,
		tokenLastVerifiedAt: time.Unix(tokenLastVerifiedAtUnix, 0),
		userDisabledCounter: userDisabledCounter,
		userSessionsCounter: userSessionsCounter,
		createdAt:           time.Unix(createdAtUnix, 0),
	}

	return session, nil
}

func decodeCachedSessionFromBytes(serialized []byte) (cachedSessionStruct, error) {
	binarySequence, err := parseBinarySequenceBytes(serialized)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to parse binary sequence bytes: %s", err.Error())
	}

	session, err := mapBinarySequenceToCachedSession(binarySequence)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to map binary sequence to session: %s", err.Error())
	}
	return session, nil
}

func mapBinarySequenceToCachedSession(binarySequence binarySequenceType) (cachedSessionStruct, error) {
	id, err := binarySequence.getString(0)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get id: %s", err.Error())
	}
	userId, err := binarySequence.getString(1)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get user id: %s", err.Error())
	}
	secretHash, err := binarySequence.get(2)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get secret hash: %s", err.Error())
	}
	tokenLastVerifiedAtUnix, err := binarySequence.getInt64(3)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get token last verified at unix: %s", err.Error())
	}
	createdAtUnix, err := binarySequence.getInt64(4)
	if err != nil {
		return cachedSessionStruct{}, fmt.Errorf("failed to get created at unix: %s", err.Error())
	}

	session := cachedSessionStruct{
		id:                  id,
		userId:              userId,
		secretHash:          secretHash,
		tokenLastVerifiedAt: time.Unix(tokenLastVerifiedAtUnix, 0),
		createdAt:           time.Unix(createdAtUnix, 0),
	}

	return session, nil
}
