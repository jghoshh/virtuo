package auth

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"os"
	"github.com/joho/godotenv"
)

// Test variables
var (
	testUsername1 = "testuser1"
	testEmail1    = "testuser1@example.com"
	testPassword1 = "Test1234"

	testUsername2 = "testuser2"
	testEmail2    = "testuser2@example.com"
	testPassword2 = "Test5678"

	testUsername3 = "testuser3"
    testEmail3    = "testuser3@example.com"
    testPassword3 = "Test9012"
)

// TestMain is the main entry point for the tests.
// It loads environment variables, initializes authentication, and runs cleanup after tests.
func TestMain(m *testing.M) {
	err := godotenv.Load("../.env")
	if err != nil {
		panic("Error loading .env file")
	}

	mongodbURI := os.Getenv("MONGODB_URI")
	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	authToken := os.Getenv("AUTH_TOKEN")

	InitAuth(mongodbURI, jwtSigningKey, authToken)

	code := m.Run()

	cleanup()

	os.Exit(code)
}

// cleanup deletes test users after each test.
func cleanup() {
	DeleteUser()
}

// TestValidateEmail tests the validateEmail function with valid and invalid emails.
func TestValidateEmail(t *testing.T) {
    assert.True(t, validateEmail("test@example.com"))
    assert.False(t, validateEmail("test@example"))
    assert.False(t, validateEmail("test@.com"))
    assert.False(t, validateEmail("test@."))
}

// TestValidatePassword tests the validatePassword function with valid and invalid passwords.
func TestValidatePassword(t *testing.T) {
    assert.True(t, validatePassword("Test1234"))
    assert.False(t, validatePassword("test"))
    assert.False(t, validatePassword("Test"))
    assert.False(t, validatePassword("1234"))
    assert.False(t, validatePassword("T1234"))
}

// TestSignUpAndSignInUser tests user sign up and sign in scenarios.
func TestSignUpAndSignInUser(t *testing.T) {

	DeleteUser()

	token, err := SignUpUser(testUsername1, testEmail1, testPassword1)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	_, err = SignUpUser(testUsername2, testEmail1, testPassword2)
	assert.Error(t, err)

	DeleteUser()

	_, err = SignUpUser("", testEmail1, testPassword1)
	assert.Error(t, err)

	_, err = SignUpUser(testUsername1, "invalid_email", testPassword1)
	assert.Error(t, err)

	_, err = SignUpUser(testUsername1, testEmail1, "short")
	assert.Error(t, err)
}

// TestIsUserAuthenticated tests if the user is authenticated.
func TestIsUserAuthenticated(t *testing.T) {

	DeleteUser()

	token, err := SignUpUser(testUsername2, testEmail2, testPassword2)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	isAuthenticated, err := IsUserAuthenticated()
	assert.NoError(t, err)
	assert.True(t, isAuthenticated)

	DeleteUser()
}

// TestUpdateUserCredentialsAndSignOut tests updating user credentials and signing out.
func TestUpdateUserCredentialsAndSignOut(t *testing.T) {

	DeleteUser()

	token, err := SignUpUser(testUsername3, testEmail3, testPassword3)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	err = UpdateUserCredentials(testEmail3, testPassword3, "newuser", "newemail@example.com", "NewPass123")
	assert.NoError(t, err)

	err = UpdateUserCredentials("invalid_email", testPassword3, "", "", "")
	assert.Error(t, err)

	err = UpdateUserCredentials(testEmail3, "Incorrect1234", "", "", "")
	assert.Error(t, err)

	DeleteUser()
}

// TestSignOutUser tests user sign out process and subsequent sign in with the same credentials.
func TestSignOutUser(t *testing.T) {
	token, err := SignUpUser(testUsername3, testEmail3, testPassword3)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	err = SignOutUser()
	assert.NoError(t, err)

	token, err = SignInUser(testEmail3, testPassword3)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	DeleteUser()
}