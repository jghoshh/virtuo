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
	"github.com/jghoshh/virtuo/lib/utils"
	"github.com/jghoshh/virtuo/lib/graph_models"
)

// jwtSigningKey is a global variable that holds the key used for signing and verifying JWT tokens. 
var jwtSigningKey string

// KeyringKey is a global variable that represents the identifier used to store and retrieve the JWT token from the system keyring. 
// This allows the application to securely store and access the token whenever it is needed for authentication purposes.
var KeyringKey string

// RefreshKeyringKey is a global variable that represents the identifier used to store and retrieve the refresh token from the system keyring. 
// This token can be used to acquire a new JWT token when the current one expires, improving the security and user experience of the application.
var RefreshKeyringKey string

// ServerURL is a global variable that stores the URL of the server that the client will connect to. 
// This URL is the endpoint to which all requests from the client will be sent.
var ServerURL string

// client is an instance of an HTTP client that is used to make requests to the server. 
// This instance is initialized with the default settings and can be used throughout the application to communicate with the server.
var client = &http.Client{}

// KeyringService is a constant that specifies the name of the service in the system keyring where the JWT token and refresh token are stored. 
// This helps to categorize and organize the tokens in the system keyring, making them easier to manage.
const KeyringService = "Virtuo"

// TokenResult is a struct type that represents the response received from an authentication service, such as SignIn or SignUp. 
// It includes the JWT token and refresh token that are returned by the service upon successful authentication.
type TokenResult struct {
	Token string
	RefreshToken string
}

// InitAuthClient is a function that initializes global variables used in this package.
//
// This function accepts four arguments:
//
// - serverURL: the URL of the server to which the requests will be sent.
// - signingKey: the key used to sign the JWT tokens.
// - authToken: the key used to store and retrieve the authentication token from the system's keyring.
// - authTokenRefresh: the key used to store and retrieve the refresh token from the system's keyring.
//
// This function must be called before using any other functions in this package.
func InitAuthClient(serverURL, signingKey, authToken, authTokenRefresh string) {
	jwtSigningKey = signingKey
	KeyringKey = authToken
	RefreshKeyringKey = authTokenRefresh
	ServerURL = serverURL
}

// decodeJWT is a function that manages the process of decoding a JWT and returning the claims contained within it.
//
// It accepts one argument:
// - tokenStr: A string containing the JWT token.
//
// This function performs several tasks:
// It uses the jwt package's Parse function to decode the token.
// If the token is invalid or an error occurs during the decoding, it returns the error. If the token is valid, it returns the claims contained within the token.
//
// The function returns an error if there was a problem with any step of the process.
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

// isJwtTokenInKeyring is a function that manages the process of checking if the system's keyring contains a JWT token.
//
// This function accepts no arguments.
//
// This function performs several tasks:
// It retrieves the JWT token from the keyring.
// If the token is not found or an error occurs during retrieval, it returns an error. If the token is found, it returns 'true' and the token.
//
// The function returns an error if there was a problem with any step of the process.
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

// ClearKeyring is a function that handles the process of clearing the JWT token and refresh token from the system's keyring atomically.
//
// This function accepts no arguments.
//
// This function performs several tasks:
// It attempts to delete both the JWT token and the refresh token from the keyring.
// If an error occurs during the deletion, it returns the error. If the deletion is successful, it returns nil.
//
// The function returns an error if there was a problem with any step of the process.
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

// IsUserAuthenticated is a function that manages the process of checking if a user is authenticated.
//
// This function accepts no arguments.
//
// This function performs several tasks:
// It checks if a valid JWT token is stored in the system's keyring.
// If the token is expired, it attempts to refresh it.
// If a valid token is found, the function returns the token. If no valid token is found or an error occurs, it returns an error.
//
// The function returns an error if there was a problem with any step of the process.
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

// sendGraphQLRequest is a utility function that sends a GraphQL request to the
// server and handles the response.
//
// It accepts four arguments:
// - query: A string containing a GraphQL query or mutation.
// - tokenString: A pointer to a string containing an authentication token, or nil if no token is available.
// - handleTokenResponse: A boolean indicating whether the function should handle TokenResult.
//    If true, the function will save the token and refresh token to the keyring.
// - variables: A variadic parameter accepting a number of map[string]interface{} arguments.
//    These represent the variables to be used in the GraphQL query or mutation.
//
// This function performs several tasks:
// It creates a request body with the provided query and, if provided, the first set of variables.
// It sends a POST request to the server with the request body, including the authentication token in the headers if it is provided.
// It reads and parses the response body into a map.
// If any errors are present in the response body, it collects and returns them as a single error.
// It extracts the 'data' field from the response body and processes it. If a token and refresh token are included in the response,
// and if handleTokenResponse is true, it saves the tokens to the keyring.
// It collects any other attributes from the 'data' field and returns them.
//
// The function returns a pointer to a TokenResult (or nil if handleTokenResponse is false or no tokens were received), a map of attributes
// extracted from the 'data' field of the response body, and an error if there was a problem with any step of the process.
func sendGraphQLRequest(query string, tokenString *string, handleTokenResponse bool, variables ...map[string]interface{}) (*TokenResult, map[string]interface{}, error) {

	// Initializing the variables that may be populated by the graphql response. 
	var token string
	var refreshToken string
    var tokenResult *TokenResult
	attributes := make(map[string]interface{})

	reqBodyData := map[string]interface{}{
		"query": query,
	}

	if len(variables) > 0 {
		reqBodyData["variables"] = variables[0]
	}

	// Create the request
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

	// Send the quest
    resp, err := client.Do(req)

    if err != nil {
        return nil, nil, fmt.Errorf("request failed: %v", err)
    }

    defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
        return nil, nil, fmt.Errorf("received non-OK response code: %d", resp.StatusCode)
    }

	// Parse the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	var responseBody map[string]interface{}

	err = json.Unmarshal(bodyBytes, &responseBody)
	if err != nil {
		return nil, nil, err
	}

	// Check if there were any errors, in which case, we would populate a slice of error messages and return immediately
    var errorMessages []string
    if errors, exists := responseBody["errors"]; exists {
        for _, err := range errors.([]interface{}) {
            errorMap := err.(map[string]interface{})
            if message, ok := errorMap["message"].(string); ok {
                errorMessages = append(errorMessages, message)
            }
        }
        return nil, nil, fmt.Errorf("errors received: %v", errorMessages)
    }

	// If there were no errors, data is expected to be there.
	data, ok := responseBody["data"].(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("response body does not contain 'data' field")
	}

	// Parse the data and populate the 'attributes' variable defined earlier
	for operationName, payload := range data {
		switch payloadMap := payload.(type) {
		case map[string]interface{}:
			switch operationName {
			case "signIn", "signUp", "refreshAccessToken":
				if t, ok := payloadMap["token"].(string); ok {
					token = t
				}
				if rt, ok := payloadMap["refreshToken"].(string); ok {
					refreshToken = rt
				}
			}
			attributes[operationName] = payloadMap
		default:
			attributes[operationName] = payload
		}
	}

	// If this function is tasked to handle token response, then handle it accordingly.
    if token != "" && handleTokenResponse {
        err := keyring.Set(KeyringService, KeyringKey, token)
        if err != nil {
            return nil, attributes, err
        }

        if refreshToken != "" {
            err = keyring.Set(KeyringService, RefreshKeyringKey, refreshToken)
            if err != nil {
                _ = keyring.Delete(KeyringService, KeyringKey)
                return nil, attributes, err
            }
        }
        tokenResult = &TokenResult{Token: token, RefreshToken: refreshToken}
    }

    return tokenResult, attributes, nil
}

// RefreshAccessToken is a function that attempts to refresh a JSON Web Token (JWT) using a refresh token stored in the keyring.
//
// The function accepts a single argument:
// - tokenStr: a string representing the current JWT token.
//
// The function performs several tasks:
// It retrieves the refresh token from the keyring.
// It constructs a GraphQL mutation query string to request a new access token using the refresh token.
// It sends this query to the GraphQL server using the sendGraphQLRequest function, which also handles the response.
// The sendGraphQLRequest function is passed the query, the current JWT token, and a map containing the refresh token as variables.
// It's also instructed to handle any received tokens by saving them to the keyring.
// If the request is successful, the function returns the new access token received in the response. If the request fails, 
// the function returns an error.
//
// The return values are:
// - A string representing the new JWT token, or an empty string if the refresh operation was not successful.
// - An error, which will be nil if the operation was successful, or an error object describing the issue if there was a problem.
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

// ConfirmEmail is a function that confirms the user's email address using the provided confirmation token.
//
// It accepts a single argument:
// - confirmationToken: a string representing the confirmation token.
//
// This function performs several tasks:
// It retrieves the current JWT token and checks if a user is authenticated.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error. If the confirmation is successful, it returns nil.
//
// The function returns an error if there was a problem with any step of the process.
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

// SignIn is a function that attempts to sign in a user with the provided username and password.
//
// It accepts two arguments:
// - username: a string representing the user's username.
// - password: a string representing the user's password.
//
// This function performs several tasks:
// It checks if a user is already signed in by calling the isJwtTokenInKeyring function.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error. If the sign in is successful, it returns the JWT token and the refresh token.
//
// The function returns a string representing the JWT token, a string representing the refresh token, and an error if there was a problem with any step of the process.
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

// SignUp is a function that attempts to sign up a new user with the provided username, email, and password.
//
// It accepts three arguments:
// - username: a string representing the user's username.
// - email: a string representing the user's email.
// - password: a string representing the user's password.
//
// This function performs several tasks:
// It validates the username, email, and password provided by the user.
// It checks if a user is already signed in by calling the isJwtTokenInKeyring function.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error. If the sign up is successful, it returns the JWT token and the refresh token.
//
// The function returns a string representing the JWT token, a string representing the refresh token, and an error if there was a problem with any step of the process.
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

// UpdateUser is a function that handles the process of updating a user's credentials.
//
// It accepts four arguments:
// - currentPassword: A string containing the current password of the user.
// - newUsername: A string containing the new username, can be an empty string if username is not being updated.
// - newEmail: A string containing the new email, can be an empty string if email is not being updated.
// - newPassword: A string containing the new password, can be an empty string if password is not being updated.
//
// This function performs several tasks:
// It retrieves the current JWT token and checks if a user is authenticated.
// It validates the new credentials provided by the user.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error. If the update is successful, it returns nil.
//
// The function returns an error if there was a problem with any step of the process.
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

// SignOut is a function that handles the process of signing out a user.
//
// This function does not require any arguments.
//
// This function performs several tasks:
// It retrieves the current JWT token and checks if a user is authenticated.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error.
// If the sign out is successful, it will also clear the JWT token and refresh token from the keyring.
//
// The function returns an error if there was a problem with any step of the process.
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

// DeleteUser is a function that handles the process of deleting a user's account.
//
// This function does not require any arguments.
//
// This function performs several tasks:
// It retrieves the current JWT token and checks if a user is authenticated.
// It prepares a GraphQL mutation and sends it to the server using the sendGraphQLRequest function.
// It handles the response from the server, if an error is received, it will return the error.
// If the deletion is successful, it will also sign out the user by calling the SignOut function.
//
// The function returns an error if there was a problem with any step of the process.
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