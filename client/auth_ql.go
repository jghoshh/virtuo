package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"github.com/form3tech-oss/jwt-go"
	"github.com/jghoshh/virtuo/auth"
	"github.com/zalando/go-keyring"
)

var jwtSigningKey string
var KeyringKey string
var RefreshKeyringKey string
var ServerURL string
var client = &http.Client{}

const KeyringService = "Virtuo"

// TokenResult is a struct that represents the result of a request to an auth service, such as SignIn or SignUp.
type TokenResult struct {
	Token        string
	RefreshToken string
}

// InitAuthClient initializes the jwtSigningKey and KeyringKey variables.
// This function must be called before using any other functions in the package.
func InitAuthClient(dbName, dbURL, serverURL, signingKey, authToken, authTokenRefresh string) {
	jwtSigningKey = signingKey
	KeyringKey = authToken
	RefreshKeyringKey = authTokenRefresh
	ServerURL = serverURL
	auth.InitAuth(dbName, dbURL, signingKey)
}

// validateEmail takes an email string as input and returns a boolean
// indicating whether the input is a valid email address.
func validateEmail(email string) bool {
	const emailPattern = `^(?i)[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}$`
	matched, err := regexp.MatchString(emailPattern, email)
	return err == nil && matched
}

// validatePassword takes a password string as input and returns a boolean indicating whether the input is a valid password.
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	containsLetter, _ := regexp.MatchString(`[a-zA-Z]`, password)
	containsNumber, _ := regexp.MatchString(`[0-9]`, password)
	return containsLetter && containsNumber
}

// decodeJWT decodes the JWT token and returns the claims if the token is valid.
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

// isJwtTokenInKeyring checks if the keyring contains some token or not and returns it if it exists.
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

// IsUserAuthenticated checks if there is a valid JWT token stored in the keyring.
// It returns the token if a valid token is found, an empty string otherwise.
// If the token is expired or invalid, it tries to refresh the token using the refresh token.
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

// sendGraphQLRequest sends a POST request to the server with the given GraphQL query, variables, and
// an optional JWT token. It also handles the TokenResponse if the handleTokenResponse flag is set to true.
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

// RefreshAccessToken sends a POST request to attain a refreshed access token from the server.
// If there's an error making the request, it returns an error.
func RefreshAccessToken(tokenStr string) (string, error) {

	refreshToken, err := keyring.Get(KeyringService, RefreshKeyringKey)

	if err != nil {
		return "", err
	}

	query := fmt.Sprintf(`
		mutation {
			refreshAccessToken(refreshToken: "%s") {
				token
				refreshToken
			}
		}
	`, refreshToken)

	tokenResponse, _, err := sendGraphQLRequest(query, &tokenStr, true)
	
	if err != nil {
		return "", err
	}

	return tokenResponse.Token, nil
}

// SignIn sends a GraphQL mutation request to signIn a user.
func SignIn(username, password string) (string, string, error) {

	isSignedIn, _, err := isJwtTokenInKeyring()

	if err != nil {
		return "", "", err
	}

	if isSignedIn {
		return "", "", errors.New("a user is already signed in")
	}

	query := fmt.Sprintf(`
		mutation {
			signIn(username: "%s", password: "%s") {
				token
				refreshToken
			}
		}
	`, username, password)
	
	tokenResponse, _, err := sendGraphQLRequest(query, nil, true)
	if err != nil {
		return "", "", err
	}

	PrintBanner("signed in successfully")

	return tokenResponse.Token, tokenResponse.RefreshToken, nil
}

// SignUp sends a GraphQL mutation request to signUp a user.
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

	if !validateEmail(email) {
		return "", "", errors.New("invalid email format")
	}

	if !validatePassword(password) {
		return "", "", errors.New("password must be at least 8 characters and contain both letters and numbers")
	}

	query := fmt.Sprintf(`
		mutation {
			signUp(user: {username: "%s", email: "%s", password: "%s"}) {
				token
				refreshToken
			}
		}
	`, username, email, password)

	tokenResponse, _, err := sendGraphQLRequest(query, nil, true)
	if err != nil {
		return "", "", err
	}

	PrintBanner("signed up successfully")

	return tokenResponse.Token, tokenResponse.RefreshToken, nil
}

// UpdateUser sends a GraphQL mutation to the server to update user information.
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
	if newEmail != "" && !validateEmail(newEmail) {
		return errors.New("new email is in invalid format")
	}
	if newPassword != "" && !validatePassword(newPassword) {
		return errors.New("new password must be at least 8 characters and contain both letters and numbers")
	}

	query := `
		mutation($input: UpdateUserInput!) {
			updateUser(input: $input) 
		}
	`

	variables := map[string]interface{}{
		"input": map[string]interface{}{
			"currentPassword": currentPassword,
			"newUsername":     newUsername,
			"newEmail":        newEmail,
			"newPassword":     newPassword,
		},
	}

	_, _, err = sendGraphQLRequest(query, &token, false, variables)
	if err != nil {
		return err
	}
	
	PrintBanner("updated user succesfully")

	return nil
}

// SignOutUser sends a GraphQL mutation to the server to invalidate the JWT token
// and then removes the JWT token and refresh token stored in the keyring, effectively signing out the user.
func SignOut() error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	query := `
		mutation {
			signOut
		}
	`
	_, _, err = sendGraphQLRequest(query, &token, false, nil)

	if err != nil {
		return err
	}

	err = keyring.Delete(KeyringService, KeyringKey)
	if err != nil {
		return errors.New("failed to delete access token from keyring: " + err.Error())
	}

	err = keyring.Delete(KeyringService, RefreshKeyringKey)
	if err != nil {
		keyring.Set(KeyringService, KeyringKey, token)
		return errors.New("failed to delete refresh token from keyring: " + err.Error())
	}

	PrintBanner("user signed out succesfully")

	return nil
}

// DeleteUser sends a GraphQL mutation to the server to delete the currently authenticated user.
// It signs out the user by calling the SignOutUser function.
func DeleteUser() error {

	token, err := IsUserAuthenticated()

	if err != nil {
		return err
	}

	if token == "" {
		return errors.New("no user is currently signed in")
	}

	query := `
		mutation {
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

	PrintBanner("user deleted succesfully")

	return nil
}