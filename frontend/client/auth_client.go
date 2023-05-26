package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"github.com/form3tech-oss/jwt-go"
	"github.com/zalando/go-keyring"
	"github.com/jghoshh/virtuo/utils"
	"github.com/jghoshh/virtuo/graph/model"
)

// jwtSigningKey is used to sign and verify JWT tokens.
var jwtSigningKey string

// KeyringKey is used to store and retrieve the JWT token from the system keyring.
var KeyringKey string

// RefreshKeyringKey is used to store and retrieve the refresh token from the system keyring.
var RefreshKeyringKey string

// ServerURL is the URL of the server the client is connecting to.
var ServerURL string

// client is the HTTP client used to make requests to the server.
var client = &http.Client{}

// KeyringService is the name of the service in the system keyring where the JWT token and refresh token are stored.
const KeyringService = "Virtuo"

// TokenResult is a struct that represents the result of a request to an auth service, such as SignIn or SignUp.
type TokenResult struct {
	Token        string
	RefreshToken string
}

// InitAuthClient initializes the jwtSigningKey and KeyringKey variables.
// This function must be called before using any other functions in the package.
func InitAuthClient(serverURL, signingKey, authToken, authTokenRefresh string) {
	jwtSigningKey = signingKey
	KeyringKey = authToken
	RefreshKeyringKey = authTokenRefresh
	ServerURL = serverURL
}

// decodeJWT decodes a JWT token and returns the claims contained within it.
// It returns an error if the token is invalid.
// Returns the claims if the token is valid, else an error.
func decodeJWT(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// isJwtTokenInKeyring checks if the system keyring contains a JWT token.
// Returns 'true' and the token if it exists, 'false' and an empty string if it doesn't.
// Returns an error if there was a problem accessing the keyring.
func isJwtTokenInKeyring() (bool, string, error) {
	jwt, err := keyring.Get(KeyringService, KeyringKey)
	if err != nil {
		if err == keyring.ErrNotFound {
			return false, "", nil
		}
		return false, "", errors.New("failed to access keyring: " + err.Error())
	}
	return true, jwt, nil
}

// ClearKeyring clears the JWT token and refresh token from the system keyring atomically.
// Returns an error if there was a problem accessing or clearing the keyring.
func ClearKeyring() error {
	accessToken, err := keyring.Get(KeyringService, KeyringKey)
	if err != nil {
		return errors.New("failed to retrieve access token from keyring: " + err.Error())
	}

	err = keyring.Delete(KeyringService, KeyringKey)
	if err != nil {
		return errors.New("failed to delete access token from keyring: " + err.Error())
	}

	err = keyring.Delete(KeyringService, RefreshKeyringKey)
	if err != nil {
		keyring.Set(KeyringService, KeyringKey, accessToken)
		return errors.New("failed to delete refresh token from keyring: " + err.Error())
	}

	return nil
}

// IsUserAuthenticated checks if the user is authenticated by checking if a valid JWT token 
// exists in the system keyring. If a valid token is found, it returns the token, else it 
// returns an empty string. If the token is expired or invalid, it tries to refresh the 
// token using the refresh token.
func IsUserAuthenticated() (string, error) {

	hasJwt, tokenStr, err := isJwtTokenInKeyring()

	if err != nil {
		return "", err
	}

	if !hasJwt {
		return "", nil
	}

	_, err = decodeJWT(tokenStr)
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				newToken, refreshErr := RefreshAccessToken(tokenStr)
				if refreshErr != nil {
					return "", refreshErr
				}
				return newToken, nil
			}
		}
		return "", err
	}

	return tokenStr, nil
}

// sendGraphQLRequest sends a GraphQL request to the server and handles the response.
// The request can be a query or mutation, and it can optionally contain variables.
// If handleTokenResponse is set to 'true', it will handle the TokenResult by saving 
// the tokens to the keyring.
// Returns the TokenResult, the HTTP response, and an error if there was a problem.
func sendGraphQLRequest(query string, tokenString *string, handleTokenResponse bool, variables ...map[string]interface{}) (*TokenResult, *http.Response, error) {

	var token string
	var refreshToken string

	reqBodyData := map[string]interface{}{
		"query": query,
	}

	if len(variables) > 0 {
		reqBodyData["variables"] = variables[0]
	}

	reqBody, err := json.Marshal(reqBodyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	req, err := http.NewRequest("POST", ServerURL+"/graphql", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if tokenString != nil {
		req.Header.Add("Authorization", "Bearer "+*tokenString)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	var responseBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &responseBody)
	if err != nil {
		return nil, nil, err
	}

	if errors, exists := responseBody["errors"]; exists {
		for _, err := range errors.([]interface{}) {
			errorMap := err.(map[string]interface{})
			if message, ok := errorMap["message"].(string); ok {
				return nil, nil, fmt.Errorf(message)
			}
		}
	}	

	data, ok := responseBody["data"].(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("response body does not contain 'data' field")
	}

	if signIn, ok := data["signIn"].(map[string]interface{}); ok {
		if t, ok := signIn["token"].(string); ok {
			token = t
		}
		if rt, ok := signIn["refreshToken"].(string); ok {
			refreshToken = rt
		}
	} else if signUp, ok := data["signUp"].(map[string]interface{}); ok {
		if t, ok := signUp["token"].(string); ok {
			token = t
		}
		if rt, ok := signUp["refreshToken"].(string); ok {
			refreshToken = rt
		}
	} else if refresh, ok := data["refreshAccessToken"].(map[string]interface{}); ok {
		if t, ok := refresh["token"].(string); ok {
			token = t
		}
		if rt, ok := refresh["refreshToken"].(string); ok {
			refreshToken = rt
		}
	} else if _, ok := data["updateUser"].(bool); ok {
		return nil, resp, nil
	} else if _, ok := data["signOut"].(bool); ok {
		return nil, resp, nil
	} else if _, ok := data["deleteUser"].(bool); ok {
		return nil, resp, nil
	} else if _, ok := data["confirmEmail"].(bool); ok {
		return nil, resp, nil
	} else if _, ok := data["checkCredentials"].(bool); ok {
		return nil, resp, nil
	} else {
		return nil, nil, errors.New("unknown response type")
	}
		
	if handleTokenResponse {
		err = keyring.Set(KeyringService, KeyringKey, token)
		if err != nil {
			return nil, nil, err
		}

		if refreshToken != "" {
			err = keyring.Set(KeyringService, RefreshKeyringKey, refreshToken)
			if err != nil {
				keyring.Delete(KeyringService, KeyringKey)
				return nil, nil, err
			}
		}
	}

	return &TokenResult{Token: token, RefreshToken: refreshToken}, resp, nil
}

// RefreshAccessToken attempts to refresh the JWT token using the refresh token.
// Returns the refreshed token if successful, else an error.
func RefreshAccessToken(tokenStr string) (string, error) {

	refreshToken, err := keyring.Get(KeyringService, RefreshKeyringKey)

	if err != nil {
		return "", err
	}

	query := `
		mutation refreshAccessToken($refreshToken: String!) {
			refreshAccessToken(refreshToken: $refreshToken) {
				token
			}
		}
	`

	vars := map[string]interface{}{
		"refreshToken": refreshToken,
	}
	
	tokenResponse, _, err := sendGraphQLRequest(query, &tokenStr, true, vars)
	
	if err != nil {
		return "", err
	}

	return tokenResponse.Token, nil
}

// ConfirmEmail attempts to confirm the user's email address using the provided confirmation token.
// Returns an error if the confirmation operation fails.
func ConfirmEmail(confirmationToken string) error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	query := `
		mutation confirmEmail($confirmationToken: String!) {
			confirmEmail(confirmationToken: $confirmationToken)
		}
	`

	vars := map[string]interface{}{
		"confirmationToken": confirmationToken,
	}
	
	_, _, err = sendGraphQLRequest(query, &token, false, vars)
	
	if err != nil {
		return err
	}

	return nil
}

// SignIn attempts to sign in a user with the provided username and password.
// Returns the JWT token and refresh token if the sign in was successful, else an error.
func SignIn(username, password string) (string, string, error) {

	isSignedIn, _, err := isJwtTokenInKeyring()

	if err != nil {
		return "", "", err
	}

	if isSignedIn {
		return "", "", errors.New("a user is already signed in")
	}

	query := `
		mutation signIn($username: String!, $password: String!) {
			signIn(username: $username, password: $password) {
				token
				refreshToken
			}
		}
	`
	
	vars := map[string]interface{}{
		"username": username,
		"password": password,
	}
	
	tokenResponse, _, err := sendGraphQLRequest(query, nil, true, vars)
	if err != nil {
		return "", "", err
	}

	return tokenResponse.Token, tokenResponse.RefreshToken, nil
}

// SignUp attempts to sign up a new user with the provided username, email, and password.
// Returns the JWT token and refresh token if the sign up was successful, else an error.
func SignUp(username, email, password string) (string, string, error) {

	isSignedIn, _, err := isJwtTokenInKeyring()

	if err != nil {
		return "", "", err
	}

	if isSignedIn {
		return "", "", errors.New("a user is already signed in")
	}

	if !(len(username) > 1) {
		return "", "", errors.New("username must be at least 2 characters")
	}

	if !utils.ValidateEmail(email) {
		return "", "", errors.New("invalid email format")
	}

	if !utils.ValidatePassword(password) {
		return "", "", errors.New("password must be at least 8 characters and contain both letters and numbers")
	}


	query := `
		mutation signUp($user: UserInput!) {
			signUp(user: $user) {
				token
				refreshToken
			}
		}
	`

	vars := map[string]interface{}{
		"user": model.UserInput{
			Username: username,
			Email:    email,
			Password: password,
		},
	}
	
	tokenResponse, _, err := sendGraphQLRequest(query, nil, true, vars)
	if err != nil {
		return "", "", err
	}

	return tokenResponse.Token, tokenResponse.RefreshToken, nil
}

// UpdateUser attempts to update the current user's information.
// It requires the current password for authentication, and the new username, email, and 
// password to update. Returns an error if the update operation fails, or if no fields to 
// update were provided.
func UpdateUser(currentPassword, newUsername, newEmail, newPassword string) error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	if newUsername == "" && newEmail == "" && newPassword == "" {
		return errors.New("nothing to update")
	}

	if newUsername != "" && len(newUsername) <= 1 {
		return errors.New("new username must be at least 2 characters")
	}
	if newEmail != "" && !utils.ValidateEmail(newEmail) {
		return errors.New("new email is in invalid format")
	}
	if newPassword != "" && !utils.ValidatePassword(newPassword) {
		return errors.New("new password must be at least 8 characters and contain both letters and numbers")
	}

	query := `
		mutation updateUser($input: UpdateUserInput!) {
			updateUser(input: $input) 
		}
	`

	input := model.UpdateUserInput{
		CurrentPassword: currentPassword,
	}

	if newUsername != "" {
		input.NewUsername = &newUsername
	}

	if newEmail != "" {
		input.NewEmail = &newEmail
	}

	if newPassword != "" {
		input.NewPassword = &newPassword
	}

	vars := map[string]interface{}{
		"input": input,
	}

	_, _, err = sendGraphQLRequest(query, &token, false, vars)
	if err != nil {
		return err
	}

	return nil
}

// SignOut signs out the current user by invalidating the JWT token on the server 
// and removing the tokens from the system keyring.
// Returns an error if the sign out operation fails.
func SignOut() error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	query := `
		mutation signOut {
			signOut
		}
	`
	_, _, err = sendGraphQLRequest(query, &token, false, nil)

	if err != nil {
		return err
	}

	err = ClearKeyring()
	if err != nil {
		return err
	}

	return nil
}

// DeleteUser deletes the currently authenticated user.
// It then signs out the user by calling the SignOutUser function.
func DeleteUser() error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	query := `
		mutation deleteUser {
			deleteUser
		}
	`
	_, _, err = sendGraphQLRequest(query, &token, false, nil)

	if err != nil {
		return err
	}

	err = SignOut()

	if err != nil {
		return err
	}

	return nil
}

func RequestPasswordReset(email string) error {
	return nil
}

func VerifyPasswordToken(email, token string) error {
	return nil
}

func ResetPassword(email, token, newPassword string) error {
	return nil
}