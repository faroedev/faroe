package faroe

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	ActionCreateSignup                             = "create_signup"
	ActionGetSignup                                = "get_signup"
	ActionDeleteSignup                             = "delete_signup"
	ActionSendSignupEmailAddressVerificationCode   = "send_signup_email_address_verification_code"
	ActionVerifySignupEmailAddressVerificationCode = "verify_signup_email_address_verification_code"
	ActionSetSignupPassword                        = "set_signup_password"
	ActionCompleteSignup                           = "complete_signup"

	ActionCreateSignin             = "create_signin"
	ActionGetSignin                = "get_signin"
	ActionDeleteSignin             = "delete_signin"
	ActionVerifySigninUserPassword = "verify_signin_user_password"
	ActionCompleteSignin           = "complete_signin"

	ActionGetSession        = "get_session"
	ActionDeleteSession     = "delete_session"
	ActionDeleteAllSessions = "delete_all_sessions"

	ActionCreateUserEmailAddressUpdate                             = "create_user_email_address_update"
	ActionGetUserEmailAddressUpdate                                = "get_user_email_address_update"
	ActionDeleteUserEmailAddressUpdate                             = "delete_user_email_address_update"
	ActionSendUserEmailAddressUpdateEmailAddressVerificationCode   = "send_user_email_address_update_email_address_verification_code"
	ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode = "verify_user_email_address_update_email_address_verification_code"
	ActionVerifyUserEmailAddressUpdateUserPassword                 = "verify_user_email_address_update_user_password"
	ActionCompleteUserEmailAddressUpdate                           = "complete_user_email_address_update"

	ActionCreateUserPasswordUpdate             = "create_user_password_update"
	ActionGetUserPasswordUpdate                = "get_user_password_update"
	ActionDeleteUserPasswordUpdate             = "delete_user_password_update"
	ActionVerifyUserPasswordUpdateUserPassword = "verify_user_password_update_user_password"
	ActionSetUserPasswordUpdateNewPassword     = "set_user_password_update_new_password"
	ActionCompleteUserPasswordUpdate           = "complete_user_password_update"

	ActionCreateUserDeletion             = "create_user_deletion"
	ActionGetUserDeletion                = "get_user_deletion"
	ActionDeleteUserDeletion             = "delete_user_deletion"
	ActionVerifyUserDeletionUserPassword = "verify_user_deletion_user_password"
	ActionCompleteUserDeletion           = "complete_user_deletion"

	ActionCreateUserPasswordReset                  = "create_user_password_reset"
	ActionGetUserPasswordReset                     = "get_user_password_reset"
	ActionDeleteUserPasswordReset                  = "delete_user_password_reset"
	ActionVerifyUserPasswordResetTemporaryPassword = "verify_user_password_reset_temporary_password"
	ActionSetUserPasswordResetNewPassword          = "set_user_password_reset_new_password"
	ActionCompleteUserPasswordReset                = "complete_user_password_reset"
)

func (server *ServerStruct) createSignupAction(actionInvocationId string, emailAddress string) (actionSignupStruct, string, error) {
	const (
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeEmailAddressNotAllowed  = "email_address_not_allowed"
		errorCodeInternalConflict        = "internal_conflict"
		errorCodeInternalError           = "internal_error"
		errorCodeInvalidEmailAddress     = "invalid_email_address"
		errorCodeRateLimited             = "rate_limited"
	)

	if !verifyEmailAddressPattern(emailAddress) {
		actionError := &actionErrorStruct{errorCodeInvalidEmailAddress}
		return actionSignupStruct{}, "", actionError
	}

	emailAddressAvailable, err := server.checkEmailAddressAvailability(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address availability: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !emailAddressAvailable {
		return actionSignupStruct{}, "", newActionError(errorCodeEmailAddressAlreadyUsed)
	}

	emailAddressAllowed, err := server.newEmailAddressChecker.CheckEmailAddress(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !emailAddressAllowed {
		return actionSignupStruct{}, "", newActionError(errorCodeEmailAddressNotAllowed)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.checkTokens(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check verify email address verification code email address rate limit tokens %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionSignupStruct{}, "", newActionError(errorCodeRateLimited)
	}

	ratelimitAllowed, err = server.sendEmailRateLimit.consumeToken(emailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return actionSignupStruct{}, "", newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionSignupStruct{}, "", newActionError(errorCodeRateLimited)
	}

	signup, signupToken, err := server.createSignup(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}

	err = server.emailSender.SendSignupEmailAddressVerificationCode(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignup)

		return actionSignupStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionSignup := server.createActionSignup(signup)

	return actionSignup, signupToken, nil
}

func (server *ServerStruct) getSignupAction(actionInvocationId string, signupToken string) (actionSignupStruct, error) {
	const (
		errorCodeInternalError      = "internal_error"
		errorCodeInvalidSignupToken = "invalid_signup_token"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return actionSignupStruct{}, newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetSignup)

		return actionSignupStruct{}, newActionError(errorCodeInternalError)
	}

	actionSignup := server.createActionSignup(signup)

	return actionSignup, nil
}

func (server *ServerStruct) deleteSignupAction(actionInvocationId string, signupToken string) error {
	const (
		errorCodeInternalError      = "internal_error"
		errorCodeInvalidSignupToken = "invalid_signup_token"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSignup)

		return newActionError(errorCodeInternalError)
	}

	err = server.deleteSignup(signup.id)
	if err != nil && errors.Is(err, errSignupNotFound) {
		return newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSignup)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) sendSignupEmailAddressVerificationCodeAction(actionInvocationId string, signupToken string) error {
	const (
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeInternalConflict            = "internal_conflict"
		errorCodeInternalError               = "internal_error"
		errorCodeInvalidSignupToken          = "invalid_signup_token"
		errorCodeRateLimited                 = "rate_limited"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendSignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	if signup.emailAddressVerified {
		return newActionError(errorCodeEmailAddressAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.checkTokens(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check verify email address verification code email address rate limit tokens: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendSignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}
	ratelimitAllowed, err = server.sendEmailRateLimit.consumeToken(signup.emailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendSignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	err = server.emailSender.SendSignupEmailAddressVerificationCode(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendSignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifySignupEmailAddressVerificationCodeAction(actionInvocationId string, signupToken string, emailAddressVerificationCode string) error {
	const (
		errorCodeEmailAlreadyVerified                  = "email_address_already_verified"
		errorCodeIncorrectEmailAddressVerificationCode = "incorrect_email_address_verification_code"
		errorCodeInternalConflict                      = "internal_conflict"
		errorCodeInternalError                         = "internal_error"
		errorCodeInvalidSignupToken                    = "invalid_signup_token"
		errorCodeRateLimited                           = "rate_limited"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if signup.emailAddressVerified {
		return newActionError(errorCodeEmailAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.consumeToken(signup.emailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify email address verification code email address rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	verificationCodeCorrect := subtle.ConstantTimeCompare([]byte(signup.emailAddressVerificationCode), []byte(emailAddressVerificationCode)) == 1
	if !verificationCodeCorrect {
		return newActionError(errorCodeIncorrectEmailAddressVerificationCode)
	}

	err = server.setSignupAsEmailAddressVerified(signup.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup as email address verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySignupEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) setSignupPasswordAction(actionInvocationId string, signupToken string, password string) error {
	const (
		errorCodeEmailAddressNotVerified = "email_address_not_verified"
		errorCodePasswordAlreadySet      = "password_already_set"
		errorCodeInternalConflict        = "internal_conflict"
		errorCodeInternalError           = "internal_error"
		errorCodeInvalidPasswordLength   = "invalid_password_length"
		errorCodeInvalidSignupToken      = "invalid_signup_token"
		errorCodeWeakPassword            = "weak_password"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetSignupPassword)

		return newActionError(errorCodeInternalError)
	}
	if !signup.emailAddressVerified {
		return newActionError(errorCodeEmailAddressNotVerified)
	}
	if signup.passwordSet {
		return newActionError(errorCodePasswordAlreadySet)
	}

	if !verifyUserPasswordPattern(password) {
		return newActionError(errorCodeInvalidPasswordLength)
	}

	passwordStrong, err := verifyUserPasswordStrength(password)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetSignupPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordStrong {
		return newActionError(errorCodeWeakPassword)
	}

	err = server.setSignupPasswordHash(signup.id, password)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetSignupPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeSignupAction(actionInvocationId string, signupToken string) (actionSessionStruct, string, error) {
	const (
		errorCodeEmailAddressNotVerified = "email_address_not_verified"
		errorCodeInternalConflict        = "internal_conflict"
		errorCodeInternalError           = "internal_error"
		errorCodeInvalidSignupToken      = "invalid_signup_token"
		errorCodeSessionNotCreated       = "session_not_created"
		errorCodePasswordNotSet          = "password_not_set"
	)

	signup, err := server.validateSignupToken(signupToken)
	if err != nil && errors.Is(err, errInvalidSignupToken) {
		return actionSessionStruct{}, "", newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !signup.emailAddressVerified {
		return actionSessionStruct{}, "", newActionError(errorCodeEmailAddressNotVerified)
	}
	if !signup.passwordSet {
		return actionSessionStruct{}, "", newActionError(errorCodePasswordNotSet)
	}

	emailAddressAllowed, err := server.newEmailAddressChecker.CheckEmailAddress(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !emailAddressAllowed {
		err = server.deleteSignup(signup.id)
		if err != nil && !errors.Is(err, errSignupNotFound) {
			errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
			server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
		}

		return actionSessionStruct{}, "", newActionError(errorCodeInvalidSignupToken)
	}

	user, err := server.userStore.CreateUser(signup.emailAddress, signup.passwordHash, signup.passwordHashAlgorithmId, signup.passwordSalt)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return actionSessionStruct{}, "", newActionError(errorCodeInternalConflict)
	}
	if err != nil && errors.Is(err, ErrUserStoreUserEmailAddressAlreadyUsed) {
		err = server.deleteSignup(signup.id)
		if err != nil && !errors.Is(err, errSignupNotFound) {
			errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
			server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
		}

		return actionSessionStruct{}, "", newActionError(errorCodeInvalidSignupToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to register user: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}

	err = server.deleteSignup(signup.id)
	if err != nil && !errors.Is(err, errSignupNotFound) {
		errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
	}

	session, sessionToken, err := server.createSession(user.Id, user.DisabledCounter, user.SessionsCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)

		return actionSessionStruct{}, "", newActionError(errorCodeSessionNotCreated)
	}

	err = server.emailSender.SendUserSignedInNotification(user.EmailAddress, user.DisplayName, session.createdAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in notification email: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
	}

	actionSession := server.createActionSession(session)

	return actionSession, sessionToken, nil
}

func (server *ServerStruct) createSigninAction(actionInvocationId string, userEmailAddress string) (actionSigninStruct, string, error) {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUserDisabled        = "user_disabled"
		errorCodeUserNotFound        = "user_not_found"
	)

	if !verifyEmailAddressPattern(userEmailAddress) {
		return actionSigninStruct{}, "", newActionError(errorCodeInvalidEmailAddress)
	}

	user, err := server.userStore.GetUserByEmailAddress(userEmailAddress)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return actionSigninStruct{}, "", newActionError(errorCodeUserNotFound)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user by email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignin)

		return actionSigninStruct{}, "", newActionError(errorCodeInternalError)
	}
	if user.Disabled {
		return actionSigninStruct{}, "", newActionError(errorCodeUserDisabled)
	}

	signin, signinToken, err := server.createSignin(user.Id, user.PasswordHashCounter, user.DisabledCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signin: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateSignin)

		return actionSigninStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionSignin := server.createActionSignin(signin)

	return actionSignin, signinToken, nil
}

func (server *ServerStruct) getSigninAction(actionInvocationId string, signinToken string) (actionSigninStruct, error) {
	const (
		errorCodeInternalError      = "internal_error"
		errorCodeInvalidSigninToken = "invalid_signin_token"
	)

	signin, _, err := server.validateSigninToken(signinToken)
	if err != nil && errors.Is(err, errInvalidSigninToken) {
		return actionSigninStruct{}, newActionError(errorCodeInvalidSigninToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signin token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetSignin)

		return actionSigninStruct{}, newActionError(errorCodeInternalError)
	}

	actionSignin := server.createActionSignin(signin)

	return actionSignin, nil
}

func (server *ServerStruct) deleteSigninAction(actionInvocationId string, signinToken string) error {
	const (
		errorCodeInternalError      = "internal_error"
		errorCodeInvalidSigninToken = "invalid_signin_token"
	)

	signin, _, err := server.validateSigninToken(signinToken)
	if err != nil && errors.Is(err, errInvalidSigninToken) {
		return newActionError(errorCodeInvalidSigninToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signin token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSignin)

		return newActionError(errorCodeInternalError)
	}

	err = server.deleteSignin(signin.id)
	if err != nil && errors.Is(err, errSigninNotFound) {
		return newActionError(errorCodeInvalidSigninToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signin: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSignin)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifySigninUserPasswordAction(actionInvocationId string, signinToken string, password string) error {
	const (
		errorCodeIncorrectPassword              = "incorrect_password"
		errorCodeInternalConflict               = "internal_conflict"
		errorCodeInternalError                  = "internal_error"
		errorCodeInvalidSigninToken             = "invalid_signin_token"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUserFirstFactorAlreadyVerified = "user_first_factor_already_verified"
	)

	signin, user, err := server.validateSigninToken(signinToken)
	if err != nil && errors.Is(err, errInvalidSigninToken) {
		return newActionError(errorCodeInvalidSigninToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signin token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySigninUserPassword)

		return newActionError(errorCodeInternalError)
	}

	if signin.userFirstFactorVerified {
		return newActionError(errorCodeUserFirstFactorAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyUserPasswordRateLimit.consumeToken(user.Id)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify user password rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySigninUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	passwordCorrect, err := server.verifyUserPassword(password, user.PasswordHash, user.PasswordHashAlgorithmId, user.PasswordSalt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySigninUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordCorrect {
		return newActionError(errorCodeIncorrectPassword)
	}

	err = server.setSigninAsUserFirstFactorVerified(signin.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signin as first factor verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifySigninUserPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeSigninAction(actionInvocationId string, signinToken string) (actionSessionStruct, string, error) {
	const (
		errorCodeInternalError              = "internal_error"
		errorCodeInvalidSigninToken         = "invalid_signin_token"
		errorCodeUserFirstFactorNotVerified = "user_first_factor_not_verified"
	)

	signin, user, err := server.validateSigninToken(signinToken)
	if err != nil && errors.Is(err, errInvalidSigninToken) {
		return actionSessionStruct{}, "", newActionError(errorCodeInvalidSigninToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signin token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignin)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !signin.userFirstFactorVerified {
		return actionSessionStruct{}, "", newActionError(errorCodeUserFirstFactorNotVerified)
	}

	session, sessionToken, err := server.createSession(user.Id, user.DisabledCounter, user.SessionsCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignin)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}

	err = server.deleteSignin(signin.id)
	if err != nil && !errors.Is(err, errSigninNotFound) {
		errorMessage := fmt.Sprintf("failed to delete signin: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignin)
	}

	err = server.emailSender.SendUserSignedInNotification(user.EmailAddress, user.DisplayName, session.createdAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in notification email: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
	}

	actionSession := server.createActionSession(session)

	return actionSession, sessionToken, nil
}

func (server *ServerStruct) getSessionAction(actionInvocationId string, sessionToken string) (actionSessionStruct, error) {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidSessionToken = "invalid_session_token"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionSessionStruct{}, newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetSession)

		return actionSessionStruct{}, newActionError(errorCodeInternalError)
	}

	actionSession := server.createActionSession(session)

	return actionSession, nil
}

func (server *ServerStruct) deleteSessionAction(actionInvocationId string, sessionToken string) error {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidSessionToken = "invalid_session_token"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSession)

		return newActionError(errorCodeInternalError)
	}

	err = server.deleteSession(session.id)
	if err != nil && errors.Is(err, errSessionNotFound) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete session: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteSession)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) deleteAllSessionsAction(actionInvocationId string, sessionToken string) error {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidSessionToken = "invalid_session_token"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteAllSessions)

		return newActionError(errorCodeInternalError)
	}

	err = server.userStore.IncrementUserSessionsCounter(session.userId, user.SessionsCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to increment user sessions counter: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteAllSessions)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) createUserEmailAddressUpdateAction(actionInvocationId string, sessionToken string, newEmailAddress string) (actionUserEmailAddressUpdateStruct, string, error) {
	const (
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeEmailAddressNotAllowed  = "email_address_not_allowed"
		errorCodeInternalConflict        = "internal_conflict"
		errorCodeInternalError           = "internal_error"
		errorCodeInvalidEmailAddress     = "invalid_email_address"
		errorCodeInvalidSessionToken     = "invalid_session_token"
		errorCodeRateLimited             = "rate_limited"
	)

	if !verifyEmailAddressPattern(newEmailAddress) {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInvalidEmailAddress)
	}

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	if user.EmailAddressCounter == math.MaxInt32 {
		errorMessage := "user email address counter limit reached"
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	emailAddressAvailable, err := server.checkEmailAddressAvailability(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address availability: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !emailAddressAvailable {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeEmailAddressAlreadyUsed)
	}

	emailAddressAllowed, err := server.newEmailAddressChecker.CheckEmailAddress(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !emailAddressAllowed {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeEmailAddressNotAllowed)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.checkTokens(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check verify email address verification code email address rate limit tokens: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeRateLimited)
	}
	ratelimitAllowed, err = server.sendEmailRateLimit.consumeToken(newEmailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeRateLimited)
	}

	userEmailAddressUpdate, userEmailAddressUpdateToken, err := server.createUserEmailAddressUpdate(session.userId, session.id, newEmailAddress, user.PasswordHashCounter, user.EmailAddressCounter, user.DisabledCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create user email address update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	err = server.emailSender.SendUserEmailAddressUpdateEmailVerificationCode(userEmailAddressUpdate.newEmailAddress, user.DisplayName, userEmailAddressUpdate.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user email address update email address verification code: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionUserEmailAddressUpdate := server.createActionUserEmailAddressUpdate(userEmailAddressUpdate)

	return actionUserEmailAddressUpdate, userEmailAddressUpdateToken, nil
}

func (server *ServerStruct) getUserEmailAddressUpdateAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string) (actionUserEmailAddressUpdateStruct, error) {
	const (
		errorCodeInternalError                      = "internal_error"
		errorCodeInvalidSessionToken                = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken = "invalid_user_email_address_update_token"
		errorCodeSessionMismatch                    = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserEmailAddressUpdateStruct{}, newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, _, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return actionUserEmailAddressUpdateStruct{}, newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserEmailAddressUpdate)

		return actionUserEmailAddressUpdateStruct{}, newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return actionUserEmailAddressUpdateStruct{}, newActionError(errorCodeSessionMismatch)
	}

	actionUserEmailAddressUpdate := server.createActionUserEmailAddressUpdate(userEmailAddressUpdate)

	return actionUserEmailAddressUpdate, nil
}

func (server *ServerStruct) deleteUserEmailAddressUpdateAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string) error {
	const (
		errorCodeInternalError                      = "internal_error"
		errorCodeInvalidSessionToken                = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken = "invalid_user_email_address_update_token"
		errorCodeSessionMismatch                    = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, _, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}

	err = server.deleteUserEmailAddressUpdate(userEmailAddressUpdate.id)
	if err != nil && errors.Is(err, errUserEmailAddressUpdateNotFound) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user email address update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) sendUserEmailAddressUpdateEmailAddressVerificationCodeAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string) error {
	const (
		errorCodeEmailAddressAlreadyVerified        = "email_address_already_verified"
		errorCodeInternalConflict                   = "internal_conflict"
		errorCodeInternalError                      = "internal_error"
		errorCodeInvalidSessionToken                = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken = "invalid_user_email_address_update_token"
		errorCodeRateLimited                        = "rate_limited"
		errorCodeSessionMismatch                    = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, user, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if userEmailAddressUpdate.newEmailAddressVerified {
		return newActionError(errorCodeEmailAddressAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.checkTokens(userEmailAddressUpdate.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check verify email address verification code email address rate limit tokens: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}
	ratelimitAllowed, err = server.sendEmailRateLimit.consumeToken((userEmailAddressUpdate.newEmailAddress))
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	err = server.emailSender.SendUserEmailAddressUpdateEmailVerificationCode(userEmailAddressUpdate.newEmailAddress, user.DisplayName, userEmailAddressUpdate.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user email address update email address verification code: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSendUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifyUserEmailAddressUpdateEmailAddressVerificationCodeAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string, emailAddressVerificationCode string) error {
	const (
		errorCodeEmailAddressAlreadyVerified           = "email_address_already_verified"
		errorCodeIncorrectEmailAddressVerificationCode = "incorrect_email_address_verification_code"
		errorCodeInternalConflict                      = "internal_conflict"
		errorCodeInternalError                         = "internal_error"
		errorCodeInvalidSessionToken                   = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken    = "invalid_user_email_address_update_token"
		errorCodeRateLimited                           = "rate_limited"
		errorCodeSessionMismatch                       = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, _, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if userEmailAddressUpdate.newEmailAddressVerified {
		return newActionError(errorCodeEmailAddressAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyEmailAddressVerificationCodeEmailAddressRateLimit.consumeToken(userEmailAddressUpdate.newEmailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify email address verification code email address rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	emailAddressVerificationCodeCorrect := subtle.ConstantTimeCompare([]byte(userEmailAddressUpdate.emailAddressVerificationCode), []byte(emailAddressVerificationCode)) == 1
	if !emailAddressVerificationCodeCorrect {
		return newActionError(errorCodeIncorrectEmailAddressVerificationCode)
	}

	err = server.setUserEmailAddressUpdateAsNewEmailAddressVerified(userEmailAddressUpdate.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user email address update as new email address verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateEmailAddressVerificationCode)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifyUserEmailAddressUpdateUserPasswordAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string, password string) error {
	const (
		errorCodeEmailAddressNotVerified            = "email_address_not_verified"
		errorCodeIncorrectPassword                  = "incorrect_password"
		errorCodeInternalConflict                   = "internal_conflict"
		errorCodeInternalError                      = "internal_error"
		errorCodeInvalidSessionToken                = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken = "invalid_user_email_address_update_token"
		errorCodeRateLimited                        = "rate_limited"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified        = "user_identity_already_verified"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, user, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if !userEmailAddressUpdate.newEmailAddressVerified {
		return newActionError(errorCodeEmailAddressNotVerified)
	}
	if userEmailAddressUpdate.userIdentityVerified {
		return newActionError(errorCodeUserIdentityAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyUserPasswordRateLimit.consumeToken(user.Id)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify user password rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	passwordCorrect, err := server.verifyUserPassword(password, user.PasswordHash, user.PasswordHashAlgorithmId, user.PasswordSalt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordCorrect {
		return newActionError(errorCodeIncorrectPassword)
	}

	err = server.setUserEmailAddressUpdateAsUserIdentityVerified(userEmailAddressUpdate.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user email address update as user identity verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserEmailAddressUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeUserEmailAddressUpdateAction(actionInvocationId string, sessionToken string, userEmailAddressUpdateToken string) error {
	const (
		errorCodeEmailAddressNotVerified            = "email_address_not_verified"
		errorCodeInternalConflict                   = "internal_conflict"
		errorCodeInternalError                      = "internal_error"
		errorCodeInvalidSessionToken                = "invalid_session_token"
		errorCodeInvalidUserEmailAddressUpdateToken = "invalid_user_email_address_update_token"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeUserIdentityNotVerified            = "user_identity_not_verified"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}

	userEmailAddressUpdate, user, err := server.validateUserEmailAddressUpdateToken(userEmailAddressUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserEmailAddressUpdateToken) {
		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}
	if userEmailAddressUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if !userEmailAddressUpdate.newEmailAddressVerified {
		return newActionError(errorCodeEmailAddressNotVerified)
	}
	if !userEmailAddressUpdate.userIdentityVerified {
		return newActionError(errorCodeUserIdentityNotVerified)
	}

	emailAddressAllowed, err := server.newEmailAddressChecker.CheckEmailAddress(userEmailAddressUpdate.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}
	if !emailAddressAllowed {
		err = server.deleteUserEmailAddressUpdate(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errSignupNotFound) {
			errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
			server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)
		}

		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}

	err = server.userStore.UpdateUserEmailAddress(userEmailAddressUpdate.userId, userEmailAddressUpdate.newEmailAddress, user.EmailAddressCounter)
	if err != nil && errors.Is(err, ErrUserStoreUserEmailAddressAlreadyUsed) {
		err = server.deleteUserEmailAddressUpdate(userEmailAddressUpdate.id)
		if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
			errorMessage := fmt.Sprintf("failed to delete user email address update: %s", err.Error())
			server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)
		}

		return newActionError(errorCodeInvalidUserEmailAddressUpdateToken)
	}
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to update user email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)

		return newActionError(errorCodeInternalError)
	}
	emailAddressUpdatedAt := server.clock.Now()

	err = server.deleteUserEmailAddressUpdate(userEmailAddressUpdate.id)
	if err != nil && !errors.Is(err, errUserEmailAddressUpdateNotFound) {
		errorMessage := fmt.Sprintf("failed to delete user email address update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)
	}

	err = server.emailSender.SendUserEmailAddressUpdatedNotification(user.EmailAddress, user.DisplayName, userEmailAddressUpdate.newEmailAddress, emailAddressUpdatedAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user email address updated notification: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserEmailAddressUpdate)
	}

	return nil
}

func (server *ServerStruct) createUserPasswordUpdateAction(actionInvocationId string, sessionToken string) (actionUserPasswordUpdateStruct, string, error) {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidSessionToken = "invalid_session_token"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserPasswordUpdateStruct{}, "", newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordUpdate)

		return actionUserPasswordUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	if user.PasswordHashCounter == math.MaxInt32 {
		errorMessage := "user password counter limit reached"
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordUpdate)

		return actionUserPasswordUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, userPasswordUpdateToken, err := server.createUserPasswordUpdate(user.Id, session.id, user.PasswordHashCounter, user.DisabledCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create user password update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordUpdate)

		return actionUserPasswordUpdateStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionUserPasswordUpdate := server.createActionUserPasswordUpdate(userPasswordUpdate)

	return actionUserPasswordUpdate, userPasswordUpdateToken, nil
}

func (server *ServerStruct) getUserPasswordUpdateAction(actionInvocationId string, sessionToken string, userPasswordUpdateToken string) (actionUserPasswordUpdateStruct, error) {
	const (
		errorCodeInternalError              = "internal_error"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeSessionMismatch            = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserPasswordUpdateStruct{}, newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserPasswordUpdate)

		return actionUserPasswordUpdateStruct{}, newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, _, err := server.validateUserPasswordUpdateToken(userPasswordUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordUpdateToken) {
		return actionUserPasswordUpdateStruct{}, newActionError(errorCodeInvalidPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserPasswordUpdate)

		return actionUserPasswordUpdateStruct{}, newActionError(errorCodeInternalError)
	}
	if userPasswordUpdate.sessionId != session.id {
		return actionUserPasswordUpdateStruct{}, newActionError(errorCodeSessionMismatch)
	}

	actionUserPasswordUpdate := server.createActionUserPasswordUpdate(userPasswordUpdate)

	return actionUserPasswordUpdate, nil
}

func (server *ServerStruct) deleteUserPasswordUpdateAction(actionInvocationId string, sessionToken string, userPasswordUpdateToken string) error {
	const (
		errorCodeInternalError                  = "internal_error"
		errorCodeInvalidUserPasswordUpdateToken = "invalid_user_password_update_token"
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeSessionMismatch                = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, _, err := server.validateUserPasswordUpdateToken(userPasswordUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordUpdateToken) {
		return newActionError(errorCodeInvalidUserPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}
	if userPasswordUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}

	err = server.deleteUserPasswordUpdate(userPasswordUpdate.id)
	if err != nil && errors.Is(err, errUserPasswordUpdateNotFound) {
		return newActionError(errorCodeInvalidUserPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user password update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifyUserPasswordUpdateUserPasswordAction(actionInvocationId string, sessionToken string, userPasswordUpdateToken string, password string) error {
	const (
		errorCodeIncorrectPassword           = "incorrect_password"
		errorCodeInternalConflict            = "internal_conflict"
		errorCodeInternalError               = "internal_error"
		errorCodeInvalidPasswordUpdateToken  = "invalid_password_update_token"
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, _, err := server.validateUserPasswordUpdateToken(userPasswordUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordUpdateToken) {
		return newActionError(errorCodeInvalidPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if userPasswordUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if userPasswordUpdate.userIdentityVerified {
		return newActionError(errorCodeUserIdentityAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyUserPasswordRateLimit.consumeToken(user.Id)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify user password rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	passwordCorrect, err := server.verifyUserPassword(password, user.PasswordHash, user.PasswordHashAlgorithmId, user.PasswordSalt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordCorrect {
		return newActionError(errorCodeIncorrectPassword)
	}

	err = server.setUserPasswordUpdateAsUserIdentityVerified(userPasswordUpdate.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user password update as user identity verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordUpdateUserPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) setUserPasswordUpdateNewPasswordAction(actionInvocationId string, sessionToken string, userPasswordUpdateToken string, password string) error {
	const (
		errorCodeInternalConflict           = "internal_conflict"
		errorCodeInternalError              = "internal_error"
		errorCodeInvalidPasswordLength      = "invalid_password_length"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeNewPasswordAlreadySet      = "new_password_already_set"
		errorCodeSessionMismatch            = "session_mismatch"
		errorCodeUserIdentityNotVerified    = "user_identity_not_verified"
		errorCodeWeakPassword               = "weak_password"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordUpdateNewPassword)

		return newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, _, err := server.validateUserPasswordUpdateToken(userPasswordUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordUpdateToken) {
		return newActionError(errorCodeInvalidPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordUpdateNewPassword)

		return newActionError(errorCodeInternalError)
	}
	if userPasswordUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if !userPasswordUpdate.userIdentityVerified {

	}
	if userPasswordUpdate.newPasswordSet {
		return newActionError(errorCodeUserIdentityNotVerified)
	}

	if !verifyUserPasswordPattern(password) {
		return newActionError(errorCodeInvalidPasswordLength)
	}

	newPasswordStrong, err := verifyUserPasswordStrength(password)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordUpdateNewPassword)

		return newActionError(errorCodeInternalError)
	}
	if !newPasswordStrong {
		return newActionError(errorCodeWeakPassword)
	}

	err = server.setUserPasswordUpdateNewPasswordHash(userPasswordUpdate.id, password)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user password update new password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordUpdateNewPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeUserPasswordUpdateAction(actionInvocationId string, sessionToken string, userPasswordUpdateToken string) error {
	const (
		errorCodeInternalConflict           = "internal_conflict"
		errorCodeInternalError              = "internal_error"
		errorCodeInvalidPasswordUpdateToken = "invalid_password_update_token"
		errorCodeInvalidSessionToken        = "invalid_session_token"
		errorCodeNewPasswordNotSet          = "new_password_not_set"
		errorCodeSessionMismatch            = "session_mismatch"
		errorCodeUserIdentityNotVerified    = "user_identity_not_verified"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}

	userPasswordUpdate, _, err := server.validateUserPasswordUpdateToken(userPasswordUpdateToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordUpdateToken) {
		return newActionError(errorCodeInvalidPasswordUpdateToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password update token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}
	if userPasswordUpdate.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if !userPasswordUpdate.userIdentityVerified {
		return newActionError(errorCodeUserIdentityNotVerified)
	}
	if !userPasswordUpdate.newPasswordSet {
		return newActionError(errorCodeNewPasswordNotSet)
	}

	err = server.userStore.UpdateUserPasswordHash(userPasswordUpdate.userId, userPasswordUpdate.newPasswordHash, userPasswordUpdate.newPasswordHashAlgorithmId, userPasswordUpdate.newPasswordSalt, user.PasswordHashCounter)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to update user password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordUpdate)

		return newActionError(errorCodeInternalError)
	}
	passwordUpdatedAt := server.clock.Now()

	err = server.deleteUserPasswordUpdate(userPasswordUpdate.id)
	if err != nil && !errors.Is(err, errUserPasswordUpdateNotFound) {
		errorMessage := fmt.Sprintf("failed to delete yser password update: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordUpdate)
	}

	err = server.emailSender.SendUserPasswordUpdatedNotification(user.EmailAddress, user.DisplayName, passwordUpdatedAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user password updated notification: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordUpdate)
	}

	return nil
}

func (server *ServerStruct) createUserDeletionAction(actionInvocationId string, sessionToken string) (actionUserDeletionStruct, string, error) {
	const (
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidSessionToken = "invalid_session_token"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserDeletionStruct{}, "", newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed tov validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserDeletion)

		return actionUserDeletionStruct{}, "", newActionError(errorCodeInternalError)
	}

	userDeletion, userDeletionToken, err := server.createUserDeletion(session.userId, session.id, user.PasswordHashCounter, user.DisabledCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create user deletion: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserDeletion)

		return actionUserDeletionStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionUserDeletion := server.createActionUserDeletion(userDeletion)

	return actionUserDeletion, userDeletionToken, nil
}

func (server *ServerStruct) getUserDeletionAction(actionInvocationId string, sessionToken string, userDeletionToken string) (actionUserDeletionStruct, error) {
	const (
		errorCodeInternalError            = "internal_error"
		errorCodeInvalidSessionToken      = "invalid_session_token"
		errorCodeInvalidUserDeletionToken = "invalid_user_deletion_token"
		errorCodeSessionMismatch          = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return actionUserDeletionStruct{}, newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserDeletion)

		return actionUserDeletionStruct{}, newActionError(errorCodeInternalError)
	}

	userDeletion, _, err := server.validateUserDeletionToken(userDeletionToken)
	if err != nil && errors.Is(err, errInvalidUserDeletionToken) {
		return actionUserDeletionStruct{}, newActionError(errorCodeInvalidUserDeletionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user deletion token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserDeletion)

		return actionUserDeletionStruct{}, newActionError(errorCodeInternalError)
	}
	if userDeletion.sessionId != session.id {
		return actionUserDeletionStruct{}, newActionError(errorCodeSessionMismatch)
	}

	actionUserDeletion := server.createActionUserDeletion(userDeletion)

	return actionUserDeletion, nil
}

func (server *ServerStruct) deleteUserDeletionAction(actionInvocationId string, sessionToken string, userDeletionToken string) error {
	const (
		errorCodeInternalError            = "internal_error"
		errorCodeInvalidSessionToken      = "invalid_session_token"
		errorCodeInvalidUserDeletionToken = "invalid_user_deletion_token"
		errorCodeSessionMismatch          = "session_mismatch"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}

	userDeletion, _, err := server.validateUserDeletionToken(userDeletionToken)
	if err != nil && errors.Is(err, errInvalidUserDeletionToken) {
		return newActionError(errorCodeInvalidUserDeletionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user deletion token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}
	if userDeletion.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}

	err = server.deleteUserDeletion(userDeletion.id)
	if err != nil && errors.Is(err, errUserDeletionNotFound) {
		return newActionError(errorCodeInvalidUserDeletionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user deletion: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifyUserDeletionUserPasswordAction(actionInvocationId string, sessionToken string, userDeletionToken string, password string) error {
	const (
		errorCodeIncorrectPassword           = "incorrect_password"
		errorCodeInternalConflict            = "internal_conflict"
		errorCodeInternalError               = "internal_error"
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidUserDeletionToken    = "invalid_user_deletion_token"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeUserIdentityAlreadyVerified = "user_identity_already_verified"
	)

	session, user, err := server.validateSessionTokenAndUser(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserDeletionUserPassword)

		return newActionError(errorCodeInternalError)
	}

	userDeletion, _, err := server.validateUserDeletionToken(userDeletionToken)
	if err != nil && errors.Is(err, errInvalidUserDeletionToken) {
		return newActionError(errorCodeInvalidUserDeletionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user deletion token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserDeletionUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if userDeletion.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if userDeletion.userIdentityVerified {
		return newActionError(errorCodeUserIdentityAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyUserPasswordRateLimit.consumeToken(user.Id)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserDeletionUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	passwordCorrect, err := server.verifyUserPassword(password, user.PasswordHash, user.PasswordHashAlgorithmId, user.PasswordSalt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserDeletionUserPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordCorrect {
		return newActionError(errorCodeIncorrectPassword)
	}

	err = server.setUserDeletionAsUserIdentityVerified(userDeletion.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user deletion as user identity verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserDeletionUserPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeUserDeletionAction(actionInvocationId string, sessionToken string, userDeletionToken string) error {
	const (
		errorCodeInternalConflict         = "internal_conflict"
		errorCodeInternalError            = "internal_error"
		errorCodeInvalidSessionToken      = "invalid_session_token"
		errorCodeInvalidUserDeletionToken = "invalid_user_deletion_token"
		errorCodeSessionMismatch          = "session_mismatch"
		errorCodeUserIdentityNotVerified  = "user_identity_not_verified"
	)

	session, err := server.validateSessionToken(sessionToken)
	if err != nil && errors.Is(err, errInvalidSessionToken) {
		return newActionError(errorCodeInvalidSessionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}

	userDeletion, _, err := server.validateUserDeletionToken(userDeletionToken)
	if err != nil && errors.Is(err, errInvalidUserDeletionToken) {
		return newActionError(errorCodeInvalidUserDeletionToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user deletion token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}
	if userDeletion.sessionId != session.id {
		return newActionError(errorCodeSessionMismatch)
	}
	if !userDeletion.userIdentityVerified {
		return newActionError(errorCodeUserIdentityNotVerified)
	}

	err = server.userStore.DeleteUser(userDeletion.userId)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserDeletion)

		return newActionError(errorCodeInternalError)
	}

	err = server.deleteUserDeletion(userDeletion.id)
	if err != nil && !errors.Is(err, errUserDeletionNotFound) {
		errorMessage := fmt.Sprintf("failed to delete user deletion: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserDeletion)
	}

	return nil
}

func (server *ServerStruct) createUserPasswordResetAction(actionInvocationId string, userEmailAddress string) (actionUserPasswordResetStruct, string, error) {
	const (
		errorCodeInternalConflict    = "internal_conflict"
		errorCodeInternalError       = "internal_error"
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeRateLimited         = "rate_limited"
		errorCodeUserDisabled        = "user_disabled"
		errorCodeUserNotFound        = "user_not_found"
	)

	if !verifyEmailAddressPattern(userEmailAddress) {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInvalidEmailAddress)
	}

	user, err := server.userStore.GetUserByEmailAddress(userEmailAddress)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeUserNotFound)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user by email address: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}
	if user.Disabled {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeUserDisabled)
	}

	if user.PasswordHashCounter == math.MaxInt32 {
		errorMessage := "user password counter limit reached"
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}

	ratelimitAllowed, err := server.verifyUserPasswordResetTemporaryPasswordUserRateLimit.checkTokens(user.Id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check verify user password reset temporary password user rate limit tokens: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeRateLimited)
	}
	ratelimitAllowed, err = server.sendEmailRateLimit.consumeToken(userEmailAddress)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume send email rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeRateLimited)
	}

	userPasswordReset, userPasswordResetToken, temporaryPassword, err := server.createUserPasswordReset(
		user.Id,
		user.PasswordHashCounter,
		user.EmailAddressCounter,
		user.DisabledCounter,
	)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create user password reset: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}

	err = server.emailSender.SendUserPasswordResetTemporaryPassword(user.EmailAddress, user.DisplayName, temporaryPassword)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user password reset temporary password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCreateUserPasswordReset)

		return actionUserPasswordResetStruct{}, "", newActionError(errorCodeInternalError)
	}

	actionUserPasswordReset := server.createActionUserPasswordReset(userPasswordReset)

	return actionUserPasswordReset, userPasswordResetToken, nil
}

func (server *ServerStruct) getUserPasswordResetAction(actionInvocationId string, userPasswordResetToken string) (actionUserPasswordResetStruct, error) {
	const (
		errorCodeInternalError                 = "internal_error"
		errorCodeInvalidUserPasswordResetToken = "invalid_user_password_reset_token"
	)

	userPasswordReset, _, err := server.validateUserPasswordResetToken(userPasswordResetToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordResetToken) {
		return actionUserPasswordResetStruct{}, newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password reset token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionGetUserPasswordReset)

		return actionUserPasswordResetStruct{}, newActionError(errorCodeInternalError)
	}

	actionUserPasswordReset := server.createActionUserPasswordReset(userPasswordReset)

	return actionUserPasswordReset, nil
}

func (server *ServerStruct) deleteUserPasswordResetAction(actionInvocationId string, userPasswordResetToken string) error {
	const (
		errorCodeInternalError                 = "internal_error"
		errorCodeInvalidUserPasswordResetToken = "invalid_user_password_reset_token"
	)

	userPasswordReset, _, err := server.validateUserPasswordResetToken(userPasswordResetToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordResetToken) {
		return newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password reset token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserPasswordReset)

		return newActionError(errorCodeInternalError)
	}

	err = server.deleteUserPasswordReset(userPasswordReset.id)
	if err != nil && errors.Is(errUserPasswordResetNotFound, errUserPasswordResetNotFound) {
		return newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user password reset: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionDeleteUserPasswordReset)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) verifyUserPasswordResetTemporaryPasswordAction(actionInvocationId string, userPasswordResetToken string, temporaryPassword string) error {
	const (
		errorCodeIncorrectTemporaryPassword     = "incorrect_temporary_password"
		errorCodeInternalConflict               = "internal_conflict"
		errorCodeInternalError                  = "internal_error"
		errorCodeInvalidUserPasswordResetToken  = "invalid_user_password_reset_token"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeUserFirstFactorAlreadyVerified = "user_first_factor_already_verified"
	)

	userPasswordReset, _, err := server.validateUserPasswordResetToken(userPasswordResetToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordResetToken) {
		return newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password reset token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordResetTemporaryPassword)

		return newActionError(errorCodeInternalError)
	}
	if userPasswordReset.userFirstFactorVerified {
		return newActionError(errorCodeUserFirstFactorAlreadyVerified)
	}

	ratelimitAllowed, err := server.verifyUserPasswordResetTemporaryPasswordUserRateLimit.consumeToken(userPasswordReset.userId)
	if err != nil && errors.Is(err, errTokenBucketRateLimitInternalConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to consume verify user password reset temporary password user rate limit token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordResetTemporaryPassword)

		return newActionError(errorCodeInternalError)
	}
	if !ratelimitAllowed {
		return newActionError(errorCodeRateLimited)
	}

	temporaryPasswordCorrect, err := server.verifyTemporaryPassword(
		temporaryPassword,
		userPasswordReset.temporaryPasswordHash,
		userPasswordReset.temporaryPasswordHashAlgorithmId,
		userPasswordReset.temporaryPasswordSalt,
	)
	if err != nil && errors.Is(err, errHashAlgorithmNotSupported) {
		err = server.deleteUserPasswordReset(userPasswordReset.id)
		if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
			errorMessage := fmt.Sprintf("failed to delete user password reset: %s", err.Error())
			server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordResetTemporaryPassword)
		}

		return newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password reset temporary password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordResetTemporaryPassword)

		return newActionError(errorCodeInternalError)
	}
	if !temporaryPasswordCorrect {
		return newActionError(errorCodeIncorrectTemporaryPassword)
	}

	err = server.setUserPasswordResetAsTemporaryPasswordVerified(userPasswordReset.id)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed set user password reset as user identity verified: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionVerifyUserPasswordResetTemporaryPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) setUserPasswordResetNewPasswordAction(actionInvocationId string, userPasswordResetToken string, password string) error {
	const (
		errorCodeInternalConflict              = "internal_conflict"
		errorCodeInternalError                 = "internal_error"
		errorCodeInvalidPasswordLength         = "invalid_password_length"
		errorCodeInvalidUserPasswordResetToken = "invalid_user_password_reset_token"
		errorCodeNewPasswordAlreadySet         = "new_password_already_set"
		errorCodeUserFirstFactorNotVerified    = "user_first_factor_not_verified"
		errorCodeWeakPassword                  = "weak_password"
	)

	userPasswordReset, _, err := server.validateUserPasswordResetToken(userPasswordResetToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordResetToken) {
		return newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password reset token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordResetNewPassword)

		return newActionError(errorCodeInternalError)
	}
	if !userPasswordReset.userFirstFactorVerified {
		return newActionError(errorCodeUserFirstFactorNotVerified)
	}
	if userPasswordReset.newPasswordSet {
		return newActionError(errorCodeNewPasswordAlreadySet)
	}

	if !verifyUserPasswordPattern(password) {
		return newActionError(errorCodeInvalidPasswordLength)
	}

	passwordStrong, err := verifyUserPasswordStrength(password)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify user password strength: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordResetNewPassword)

		return newActionError(errorCodeInternalError)
	}
	if !passwordStrong {
		return newActionError(errorCodeWeakPassword)
	}

	err = server.setUserPasswordResetNewPasswordHash(userPasswordReset.id, password)
	if err != nil && errors.Is(err, errConflict) {
		return newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set user password reset new password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionSetUserPasswordResetNewPassword)

		return newActionError(errorCodeInternalError)
	}

	return nil
}

func (server *ServerStruct) completeUserPasswordResetAction(actionInvocationId string, userPasswordResetToken string) (actionSessionStruct, string, error) {
	const (
		errorCodeInternalConflict              = "internal_conflict"
		errorCodeInternalError                 = "internal_error"
		errorCodeInvalidUserPasswordResetToken = "invalid_user_password_reset_token"
		errorCodeNewPasswordNotSet             = "new_password_not_set"
		errorCodeSessionNotCreated             = "session_not_created"
		errorCodeUserFirstFactorNotVerified    = "user_first_factor_not_verified"
	)

	userPasswordReset, user, err := server.validateUserPasswordResetToken(userPasswordResetToken)
	if err != nil && errors.Is(err, errInvalidUserPasswordResetToken) {
		return actionSessionStruct{}, "", newActionError(errorCodeInvalidUserPasswordResetToken)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate user password reset token: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordReset)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}
	if !userPasswordReset.userFirstFactorVerified {
		return actionSessionStruct{}, "", newActionError(errorCodeUserFirstFactorNotVerified)
	}
	if !userPasswordReset.newPasswordSet {
		return actionSessionStruct{}, "", newActionError(errorCodeNewPasswordNotSet)
	}

	err = server.userStore.UpdateUserPasswordHash(
		userPasswordReset.userId,
		userPasswordReset.newPasswordHash,
		userPasswordReset.newPasswordHashAlgorithmId,
		userPasswordReset.newPasswordSalt,
		userPasswordReset.userPasswordHashCounter,
	)
	if err != nil && errors.Is(err, ErrUserStoreUserNotFound) {
		return actionSessionStruct{}, "", newActionError(errorCodeInternalConflict)
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to update user password: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordReset)

		return actionSessionStruct{}, "", newActionError(errorCodeInternalError)
	}
	passwordResetAt := server.clock.Now()

	err = server.deleteUserPasswordReset(userPasswordReset.id)
	if err != nil && !errors.Is(err, errUserPasswordResetNotFound) {
		errorMessage := fmt.Sprintf("failed to delete user password reset: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordReset)
	}

	err = server.emailSender.SendUserPasswordUpdatedNotification(user.EmailAddress, user.DisplayName, passwordResetAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send user password reset notification: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordReset)
	}

	session, sessionToken, err := server.createSession(user.Id, user.DisabledCounter, user.SessionsCounter)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create session : %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteUserPasswordReset)

		return actionSessionStruct{}, "", newActionError(errorCodeSessionNotCreated)
	}

	err = server.emailSender.SendUserSignedInNotification(user.EmailAddress, user.DisplayName, session.createdAt)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in notification email: %s", err.Error())
		server.errorLogger.LogActionError(server.clock.Now(), errorMessage, actionInvocationId, ActionCompleteSignup)
	}

	actionSession := server.createActionSession(session)

	return actionSession, sessionToken, nil
}

type actionSignupStruct struct {
	id                   string
	unregisteredUserId   string
	emailAddress         string
	emailAddressVerified bool
	passwordSet          bool
	createdAt            time.Time
	expiresAt            time.Time
}

func (server *ServerStruct) createActionSignup(signup signupStruct) actionSignupStruct {
	actionSignup := actionSignupStruct{
		id:                   signup.id,
		emailAddress:         signup.emailAddress,
		emailAddressVerified: signup.emailAddressVerified,
		passwordSet:          signup.passwordSet,
		createdAt:            signup.createdAt,
		expiresAt:            signup.createdAt.Add(signupExpiration),
	}
	return actionSignup
}

type actionSigninStruct struct {
	id                      string
	userId                  string
	userFirstFactorVerified bool
	createdAt               time.Time
	expiresAt               time.Time
}

func (server *ServerStruct) createActionSignin(signin signinStruct) actionSigninStruct {
	actionSignin := actionSigninStruct{
		id:                      signin.id,
		userId:                  signin.userId,
		userFirstFactorVerified: signin.userFirstFactorVerified,
		createdAt:               signin.createdAt,
		expiresAt:               signin.createdAt.Add(signinExpiration),
	}
	return actionSignin
}

type actionSessionStruct struct {
	id               string
	userId           string
	createdAt        time.Time
	expiresAt        time.Time
	expiresAtDefined bool
}

func (server *ServerStruct) createActionSession(session cachedSessionStruct) actionSessionStruct {
	actionSession := actionSessionStruct{
		id:               session.id,
		userId:           session.userId,
		createdAt:        session.createdAt,
		expiresAtDefined: false,
	}
	if server.sessionConfig.Expiration > 0 {
		actionSession.expiresAt = session.createdAt.Add(server.sessionConfig.Expiration)
		actionSession.expiresAtDefined = true
	}
	return actionSession
}

type actionUserEmailAddressUpdateStruct struct {
	id                      string
	userId                  string
	sessionId               string
	newEmailAddress         string
	newEmailAddressVerified bool
	userIdentityVerified    bool
	createdAt               time.Time
	expiresAt               time.Time
}

func (server *ServerStruct) createActionUserEmailAddressUpdate(userEmailAddressUpdate userEmailAddressUpdateStruct) actionUserEmailAddressUpdateStruct {
	actionUserEmailAddressUpdate := actionUserEmailAddressUpdateStruct{
		id:                      userEmailAddressUpdate.id,
		userId:                  userEmailAddressUpdate.userId,
		sessionId:               userEmailAddressUpdate.sessionId,
		newEmailAddress:         userEmailAddressUpdate.newEmailAddress,
		newEmailAddressVerified: userEmailAddressUpdate.newEmailAddressVerified,
		userIdentityVerified:    userEmailAddressUpdate.userIdentityVerified,
		createdAt:               userEmailAddressUpdate.createdAt,
		expiresAt:               userEmailAddressUpdate.createdAt.Add(userEmailAddressUpdateExpiration),
	}
	return actionUserEmailAddressUpdate
}

type actionUserPasswordUpdateStruct struct {
	id                   string
	userId               string
	sessionId            string
	userIdentityVerified bool
	newPasswordSet       bool
	createdAt            time.Time
	expiresAt            time.Time
}

func (server *ServerStruct) createActionUserPasswordUpdate(userPasswordUpdate userPasswordUpdateStruct) actionUserPasswordUpdateStruct {
	actionUserPasswordUpdate := actionUserPasswordUpdateStruct{
		id:                   userPasswordUpdate.id,
		userId:               userPasswordUpdate.userId,
		sessionId:            userPasswordUpdate.sessionId,
		userIdentityVerified: userPasswordUpdate.userIdentityVerified,
		newPasswordSet:       userPasswordUpdate.newPasswordSet,
		createdAt:            userPasswordUpdate.createdAt,
		expiresAt:            userPasswordUpdate.createdAt.Add(userPasswordUpdateExpiration),
	}
	return actionUserPasswordUpdate
}

type actionUserDeletionStruct struct {
	id                   string
	userId               string
	sessionId            string
	userIdentityVerified bool
	createdAt            time.Time
	expiresAt            time.Time
}

func (server *ServerStruct) createActionUserDeletion(userDeletion userDeletionStruct) actionUserDeletionStruct {
	actionUserDeletion := actionUserDeletionStruct{
		id:                   userDeletion.id,
		userId:               userDeletion.userId,
		sessionId:            userDeletion.sessionId,
		userIdentityVerified: userDeletion.userIdentityVerified,
		createdAt:            userDeletion.createdAt,
		expiresAt:            userDeletion.createdAt.Add(userDeletionExpiration),
	}
	return actionUserDeletion
}

type actionUserPasswordResetStruct struct {
	id                      string
	userId                  string
	userFirstFactorVerified bool
	newPasswordSet          bool
	createdAt               time.Time
	expiresAt               time.Time
}

func (server *ServerStruct) createActionUserPasswordReset(userPasswordReset userPasswordResetStruct) actionUserPasswordResetStruct {
	actionUserPasswordReset := actionUserPasswordResetStruct{
		id:                      userPasswordReset.id,
		userId:                  userPasswordReset.userId,
		userFirstFactorVerified: userPasswordReset.userFirstFactorVerified,
		newPasswordSet:          userPasswordReset.newPasswordSet,
		createdAt:               userPasswordReset.createdAt,
		expiresAt:               userPasswordReset.createdAt.Add(userPasswordResetExpiration),
	}
	return actionUserPasswordReset
}

type EmailSenderInterface interface {
	// Send an email to emailAddress.
	SendSignupEmailAddressVerificationCode(emailAddress string, emailAddressVerificationCode string) error

	// Send an email to emailAddress.
	// displayName may be an empty string.
	SendUserEmailAddressUpdateEmailVerificationCode(emailAddress string, displayName string, emailAddressVerificationCode string) error

	// Send an email to emailAddress.
	// displayName may be an empty string.
	SendUserPasswordResetTemporaryPassword(emailAddress string, displayName string, temporaryPassword string) error

	// Send an email to emailAddress.
	// displayName may be an empty string.
	SendUserSignedInNotification(emailAddress string, displayName string, timestamp time.Time) error

	// Send an email to emailAddress.
	// displayName may be an empty string.
	SendUserEmailAddressUpdatedNotification(emailAddress string, displayName string, newEmailAddress string, timestamp time.Time) error

	// Send an email to emailAddress.
	// displayName may be an empty string.
	SendUserPasswordUpdatedNotification(emailAddress string, displayName string, timestamp time.Time) error
}

type actionErrorStruct struct {
	errorCode string
}

func newActionError(errorCode string) *actionErrorStruct {
	return &actionErrorStruct{errorCode}
}

func (actionError *actionErrorStruct) Error() string {
	return actionError.errorCode
}

type ActionErrorLoggerInterface interface {
	LogActionError(timestamp time.Time, message string, actionInvocationId string, action string)
}

type ActionInvocationEndpointClientInterface interface {
	// Sends a request to an action invocation endpoint with the request body.
	// Returns the string body of a 200 response.
	// An error is returned if a 200 response could be received (after one or several attempts).
	SendActionInvocationEndpointRequest(body string) (string, error)
}
