package faroe

import (
	"time"

	"golang.org/x/sync/semaphore"
)

// Use [NewServer].
type ServerStruct struct {
	storage StorageInterface

	userStore UserStoreInterface

	errorLogger                    ActionErrorLoggerInterface
	userPasswordHashAlgorithms     []PasswordHashAlgorithmInterface
	temporaryPasswordHashAlgorithm PasswordHashAlgorithmInterface
	passwordHashingSemaphore       *semaphore.Weighted
	clock                          ClockInterface
	newEmailAddressChecker         EmailAddressCheckerInterface
	emailSender                    EmailSenderInterface
	sessionConfig                  SessionConfigStruct

	verifyUserPasswordRateLimit                             *tokenBucketRateLimit
	sendEmailRateLimit                                      *tokenBucketRateLimit
	verifyEmailAddressVerificationCodeEmailAddressRateLimit *tokenBucketRateLimit
	verifyUserPasswordResetTemporaryPasswordUserRateLimit   *tokenBucketRateLimit
}

// All interfaces must be defined and cannot be nil.
//
// maxConcurrentPasswordHashingProcesses defines the maximum number of concurrent processes for user password and temporary password hashing.
//
// emailAddressChecker is used for checking email addresses for signup and new email addresses of user email address updates.
// It is not used in for sign ins or user password resets.
//
// InactivityTimeout and ActivityCheckInterval should be a non-zero value in sessionConfig.
func NewServer(
	storage StorageInterface,
	userStore UserStoreInterface,
	errorLogger ActionErrorLoggerInterface,
	userPasswordHashAlgorithms []PasswordHashAlgorithmInterface,
	temporaryPasswordHashAlgorithm PasswordHashAlgorithmInterface,
	maxConcurrentPasswordHashingProcesses int,
	clock ClockInterface,
	newEmailAddressChecker EmailAddressCheckerInterface,
	emailSender EmailSenderInterface,
	sessionConfig SessionConfigStruct,
) *ServerStruct {
	verifyUserPasswordRateLimit := newTokenBucketRateLimit(storage, storageKeyPrefixVerifyUserPasswordTokenBucket, clock, 5, time.Minute)
	sendEmailRateLimit := newTokenBucketRateLimit(storage, storageKeyPrefixSendEmailTokenBucket, clock, 5, 30*time.Minute)
	verifyEmailAddressVerificationCodeEmailAddressRateLimit := newTokenBucketRateLimit(storage, storageKeyPrefixVerifyEmailAddressVerificationCodeEmailAddressTokenBucket, clock, 5, time.Minute)
	verifyUserPasswordResetTemporaryPasswordUserRateLimit := newTokenBucketRateLimit(storage, storageKeyPrefixVerifyUserPasswordResetTemporaryPasswordUserTokenBucket, clock, 5, time.Minute)

	action := &ServerStruct{
		storage:                        storage,
		userStore:                      userStore,
		errorLogger:                    errorLogger,
		userPasswordHashAlgorithms:     userPasswordHashAlgorithms,
		temporaryPasswordHashAlgorithm: temporaryPasswordHashAlgorithm,
		passwordHashingSemaphore:       semaphore.NewWeighted(int64(maxConcurrentPasswordHashingProcesses)),
		clock:                          clock,
		newEmailAddressChecker:         newEmailAddressChecker,
		emailSender:                    emailSender,
		sessionConfig:                  sessionConfig,

		verifyUserPasswordRateLimit:                             verifyUserPasswordRateLimit,
		sendEmailRateLimit:                                      sendEmailRateLimit,
		verifyEmailAddressVerificationCodeEmailAddressRateLimit: verifyEmailAddressVerificationCodeEmailAddressRateLimit,
		verifyUserPasswordResetTemporaryPasswordUserRateLimit:   verifyUserPasswordResetTemporaryPasswordUserRateLimit,
	}

	return action
}
