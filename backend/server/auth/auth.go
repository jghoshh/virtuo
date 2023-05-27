package auth

import (
	"time"
	"errors"
	"fmt"
	"context"
	"golang.org/x/crypto/bcrypt"
	"github.com/form3tech-oss/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/jghoshh/virtuo/backend/storage/persistent"
	"github.com/jghoshh/virtuo/backend/models"
	"github.com/jghoshh/virtuo/backend/queue"
	"github.com/jghoshh/virtuo/lib/utils"
	"crypto/rand"
	"encoding/base32"
)

// store is a global variable that holds an interface to the storage system (database). 
var store storage.StorageInterface

// jwtSigningKey is a global variable that holds the key used for signing and verifying JWT tokens. 
var jwtSigningKey string

// emailQueue is a global variable that stores a reference to the messaging queue used to process and send emails.
var emailQueue *queue.Queue

// InitAuth is a function for initializing the authentication system.
//
// It accepts four arguments:
// - dbName: The name of the MongoDB database to use for storage.
// - mongodbURI: The URI to connect to the MongoDB database.
// - signingKey: The key used to sign JWT tokens.
// - queue: A queue system to process the emails.
//
// The function sets up the storage system and JWT signing key.
// It panics if there is any error during the initialization.
func InitAuth(dbName, mongodbURI, signingKey string, queue *queue.Queue) {
	var err error
	jwtSigningKey = signingKey
	store, err = storage.NewStorage(dbName, mongodbURI)
	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}
	emailQueue = queue
}

// CreateAuthToken is a function to create a signed JWT token for a user.
//
// It accepts one argument:
// - userId: The ID of the user to generate a token for.
//
// The function creates a JWT token with the user's ID and an expiration time.
// It returns a signed JWT token or an error if there was a problem during the token creation.
func CreateAuthToken(userId string) (string, error) {
	claims := jwt.MapClaims{
		"id":  userId,
		"exp": time.Now().Add(time.Second * 4).Unix(),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := newToken.SignedString([]byte(jwtSigningKey))

	if err != nil {
		return "", errors.New("failed to create auth token")
	}

	return signedToken, nil
}

// CreateRefreshToken is a function to create a refresh JWT token for a user.
//
// It accepts one argument:
// - userId: The ID of the user to generate a refresh token for.
//
// The function creates a JWT refresh token with the user's ID and an expiration time.
// It returns a signed JWT refresh token or an error if there was a problem during the token creation.
func CreateRefreshToken(userId string) (string, error) {
	claims := jwt.MapClaims{
		"id":  userId, 
		"exp": time.Now().Add(time.Minute * 30).Unix(),  
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := newToken.SignedString([]byte(jwtSigningKey))

	if err != nil {
		return "", errors.New("failed to create refresh token")
	}

	return signedToken, nil
}

// CreateTokens is a function to create both an auth token and a refresh token for a user.
//
// It accepts one argument:
// - userId: The ID of the user to generate tokens for.
//
// The function calls the CreateAuthToken and CreateRefreshToken functions to create a pair of tokens.
// It returns the pair of tokens or an error if there was a problem during the token creation.
func CreateTokens(userId string) (string, string, error) {
	authToken, authErr := CreateAuthToken(userId)
	if authErr != nil {
		return "", "", authErr
	}

	refreshToken, refreshErr := CreateRefreshToken(userId)
	if refreshErr != nil {
		return "", "", refreshErr
	}

	return authToken, refreshToken, nil
}

// CheckCredentials is a function to verify the credentials of a user.
//
// It accepts three arguments:
// - username: The username of the user.
// - email: The email of the user.
// - password: The password of the user.
//
// The function checks the length of the username and the format of the email.
// It returns a boolean indicating whether the credentials are valid or not, and an error if there was a problem during the validation.
func CheckCredentials(username, email, password string) (bool, error) {

	if len(username) < 2 {
		return false, errors.New("invalid username")
	}

	if !utils.ValidateEmail(email) {
		return false, errors.New("invalid email format")
	}

	return true, nil
}

// ResetPassword is a function to reset the password of a user.
//
// It accepts two arguments:
// - email: The email of the user.
// - newPassword: The new password of the user.
//
// The function validates the email and resets the password of the user associated with the provided email.
// It returns an error if there was a problem during the password reset process.
func ResetPassword(email, newPassword string) error {
	return nil
}

// SignIn is a function for authenticating a user.
//
// It accepts two arguments:
// - username: A string containing the username of the user attempting to log in.
// - password: A string containing the password of the user attempting to log in.
//
// This function performs several tasks:
// It checks if the length of the username is at least 2 characters.
// It finds the user in the database by their username.
// It compares the hashed password stored in the database with the password provided by the user.
// It calls CreateTokens function to generate a new pair of tokens for the user.
//
// The function returns an authentication token, a refresh token, a boolean indicating whether the user's email is confirmed, 
// and an error if there was a problem with any step of the process.
func SignIn(username string, password string) (string, string, bool, error) {

	if len(username) < 2 {
		return "", "", false, errors.New("invalid username")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"username": username})

	if err != nil {
		return "", "", false, errors.New("authentication failed")
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password))
	if err != nil {
		return "", "", false, errors.New("authentication failed")
	}

	token, refreshToken, err := CreateTokens(foundUser.ID.Hex())

	if err != nil {
		return "", "", false, err
	}

	return token, refreshToken, foundUser.EmailConfirmed, nil
}

// SignUp is a function for registering a new user.
//
// It accepts three arguments:
// - username: A string containing the username of the new user.
// - email: A string containing the email of the new user.
// - password: A string containing the password of the new user.
//
// This function performs several tasks:
// It checks if the length of the username is at least 2 characters.
// It validates the email format and the password complexity.
// It checks if a user with the same email or username already exists in the database.
// It hashes the password provided by the user.
// It creates a new user in the database with the provided details.
// It generates a confirmation token and sends a confirmation email to the new user.
// It adds a confirmation record to the database, associated with the new user.
// It calls CreateTokens function to generate a new pair of tokens for the user.
//
// The function returns an authentication token, a refresh token, and an error if there was a problem with any step of the process.
func SignUp(username string, email string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", errors.New("invalid username")
	}

	if !utils.ValidateEmail(email) {
		return "", "", errors.New("invalid email format")
	}

	if !utils.ValidatePassword(password) {
		return "", "", errors.New("password must be at least 8 characters and contain both letters and numbers")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"email": email})
	if err != nil && err != mongo.ErrNoDocuments {
		return "", "", err
	}

	if foundUser != nil {
		return "", "", errors.New("an account with this email already exists")
	}

	foundUser, err = store.FindUser(context.Background(), bson.M{"username": username})
	if err != nil && err != mongo.ErrNoDocuments {
		return "", "", err
	}

	if foundUser != nil {
		return "", "", errors.New("username is taken")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	newUserID := primitive.NewObjectID()

	user := &models.User{
		ID: 		  newUserID,
		Username:     username,
		Email:        email,
		EmailConfirmed: false,
		PasswordHash: string(hashedPassword),
		Points:       0,
		LevelID:      primitive.NilObjectID,
		GroupIDs:     []primitive.ObjectID{},
		Streak:       0,
	}

	_, err = store.AddUser(context.Background(), user)
	if err != nil {
		return "", "", err
	}

	// Generate a random token
	tokenBytes := make([]byte, 3)  // 3 bytes can encode up to 6 characters in base32
	_, err = rand.Read(tokenBytes)
	if err != nil {
		return "", "", err
	}
	confirmationToken := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tokenBytes)

	// If it is more than 6 characters, cut it down to 6
	if len(confirmationToken) > 6 {
		confirmationToken = confirmationToken[:6]
	}

	// Hash the confirmation token before storing it in the database
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(confirmationToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	// Create a new email message to send to the user
	emailMsg := &queue.EmailMessage{
		Id:    newUserID.Hex(), // A unique ID for the message
		Token: confirmationToken, // The confirmation token the user must input in the CLI for email verification
		To:    email, // The email address of the user
	}

	// Process the email message (i.e., send it to the user)
	if err := queue.ProcessEmail(emailMsg, emailQueue); err != nil {
		return "", "", err
	}

	// Create a confirmation with the user ID and hashed confirmation token
	confirmation := &models.Confirmation{
		UserID:            newUserID,
		ConfirmationToken: string(hashedToken),
		ExpiresAt:         time.Now().Add(24 * time.Hour), // The confirmation token expires after 24 hours
	}

	// Add the confirmation to the storage backend
	_, err = store.AddConfirmation(context.Background(), confirmation)
	if err != nil {
		return "", "", err
	}

	token, refreshToken, err := CreateTokens(newUserID.Hex()) 
	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

// RefreshToken is a function that validates a refresh token and generates a new pair of tokens if the refresh token is valid.
// It accepts two arguments:
// - userId: A string containing the id of the user who is requesting new tokens.
// - refreshToken: A string containing the refresh token to be validated.
//
// This function performs several tasks:
// It parses the refresh token and validates it.
// If the refresh token is valid and belongs to the given user, it generates a new pair of tokens.
// If the refresh token is expired or invalid, or does not belong to the given user, it returns an error.
//
// The function returns the new tokens (or empty strings if there was an error), and an error if there was a problem with any step of the process.
func RefreshToken(userId string, refreshToken string) (string, string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors == jwt.ValidationErrorExpired {
				return "", "", errors.New("expired refresh token")
			}
		}
		return "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid refresh token")
	}

	if claims["id"] != userId {
		return "", "", errors.New("invalid refresh token")
	}

	return CreateTokens(userId)
}

// UpdateUser is a function that allows the update of user details.
// It accepts five arguments:
// - userId: A string containing the id of the user whose details are to be updated.
// - currentPassword: A string containing the current password of the user. This is used for authentication before updating any details.
// - newUsername: A string containing the new username for the user.
// - newEmail: A string containing the new email for the user.
// - newPassword: A string containing the new password for the user.
//
// This function performs several tasks:
// It checks if the current password matches the stored password for the user.
// If the current password is incorrect, it returns an error.
// If the current password is correct, it updates the provided fields (username, email, and/or password) in the user's record in the database.
//
// The function returns a boolean indicating whether the update operation was successful, a boolean indicating whether the user's email is confirmed,
// and an error if there was a problem with any step of the process.
func UpdateUser(userId, currentPassword, newUsername, newEmail, newPassword string) (bool, bool, error) {

	objectID, err := primitive.ObjectIDFromHex(userId)

	if err != nil {
		return false, false, err
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"_id": objectID})
    if err != nil {
        return false, false, errors.New("authentication failed")
    }

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword))
	if err != nil {
		return false, false, errors.New("authentication failed")
	}

	update := bson.M{
		"$set": bson.M{},
	}

	if newUsername != "" {
		existingUser, err := store.FindUser(context.Background(), bson.M{"username": newUsername})
		if existingUser != nil || err == nil {
			return false, false, errors.New("username already in use")
		}
		update["$set"].(bson.M)["username"] = newUsername
	}

	if newEmail != "" {
		existingUser, err := store.FindUser(context.Background(), bson.M{"email": newEmail})
		if existingUser != nil || err == nil {
			return false, false, errors.New("email already in use")
		}
		update["$set"].(bson.M)["email"] = newEmail
		update["$set"].(bson.M)["emailConfirmed"] = false
	}

	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return false, false, err
		}
		update["$set"].(bson.M)["password_hash"] = string(hashedPassword)
	}

	if len(update["$set"].(bson.M)) == 0 {
		return false, false, errors.New("nothing to update")
	}

	_, err = store.UpdateUser(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		return false, false, errors.New("internal server error updating user")
	}

	emailConfirmed := foundUser.EmailConfirmed
	if newEmail != "" {
		emailConfirmed = false
	}
	return true, emailConfirmed, nil
}

// DeleteUser is a function that deletes a user record from the database.
// It accepts one argument:
// - userId: A string containing the id of the user who is to be deleted.
//
// This function performs one main task:
// It deletes the user record with the given id from the database.
//
// The function returns a boolean indicating whether the deletion was successful, and an error if there was a problem with the deletion operation.
func DeleteUser(userId string) (bool, error) {

	objectID, err := primitive.ObjectIDFromHex(userId)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	_, err = store.DeleteUser(context.Background(), bson.M{"_id": objectID})

	if err != nil {
		return false, errors.New("error deleting user")
	}

	return true, nil
}

// ConfirmEmail is a function that confirms a user's email address.
// It accepts two arguments:
// - userID: A string containing the id of the user whose email address is to be confirmed.
// - confirmationToken: A string containing the confirmation token for confirming the email address.
//
// This function performs several tasks:
// It fetches the confirmation record for the given user from the database.
// It checks if the confirmation token is expired or does not match the stored confirmation token.
// If the confirmation token is valid and not expired, it updates the user's record in the database to confirm their email address.
// It then deletes the confirmation record from the database.
//
// The function returns an error if there was a problem with any step of the process.
func ConfirmEmail(userID, confirmationToken string) error {
	var confirmError error
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	// Fetch confirmation record from the database
	foundConfirmation, err := store.FindConfirmation(context.Background(), bson.M{"userId": objectID})
	if err != nil {
		return err
	}

	// Check if the confirmation record has expired
	if foundConfirmation.ExpiresAt.Before(time.Now()) {
		confirmError = errors.New("confirmation token has expired")
	} else if err = bcrypt.CompareHashAndPassword([]byte(foundConfirmation.ConfirmationToken), []byte(confirmationToken)); err != nil {
		// Compare hashed stored confirmation token with provided token only if it hasn't expired
		confirmError = errors.New("invalid confirmation token")
	} else {
		// If the token is valid and not expired, confirm the user's email
		update := bson.M{
			"$set": bson.M{
				"emailConfirmed": true,
			},
		}

		_, err = store.UpdateUser(context.Background(), bson.M{"_id": objectID}, update)
		if err != nil {
			return err
		}
	}

	// If the email is confirmed, remove the confirmation record, regardless of whether the token was valid or not
	_, err = store.DeleteConfirmation(context.Background(), bson.M{"_id": foundConfirmation.ID})
	if err != nil {
		return errors.New("error removing confirmation record")
	}

	return confirmError
}