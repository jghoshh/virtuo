package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.31

import (
	"context"
	"fmt"

	"github.com/jghoshh/virtuo/backend/server/auth"
	contextKey "github.com/jghoshh/virtuo/backend/server/context_key"
	model "github.com/jghoshh/virtuo/lib/graph_models"
	"github.com/jghoshh/virtuo/lib/utils"
)

// SignUp is the resolver for the signUp field.
func (r *mutationResolver) SignUp(ctx context.Context, user model.UserInput) (*model.AuthPayload, error) {
	if len(user.Username) < 2 {
		return nil, fmt.Errorf("username must be at least 2 characters")
	}

	if !utils.ValidateEmail(user.Email) {
		return nil, fmt.Errorf("invalid email format")
	}

	if !utils.ValidatePassword(user.Password) {
		return nil, fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
	}

	token, refreshToken, err := auth.SignUp(user.Username, user.Email, user.Password)

	if err != nil {
		return nil, err
	}

	authPayload := &model.AuthPayload{
		Token:        token,
		RefreshToken: refreshToken,
	}

	return authPayload, nil
}

// SignIn is the resolver for the signIn field.
func (r *mutationResolver) SignIn(ctx context.Context, username string, password string) (*model.SignInPayload, error) {
	token, refreshToken, confirmed, err := auth.SignIn(username, password)

	if err != nil {
		return nil, err
	}

	signInPayload := &model.SignInPayload{
		Token:          token,
		RefreshToken:   refreshToken,
		EmailConfirmed: confirmed,
	}

	return signInPayload, nil
}

// SignOut is the resolver for the signOut field.
func (r *mutationResolver) SignOut(ctx context.Context) (bool, error) {
	// For now and for simplicity, we will not implement server side sign out logic to invalidate tokens.
	return true, nil
}

// RefreshAccessToken is the resolver for the refreshAccessToken field.
func (r *mutationResolver) RefreshAccessToken(ctx context.Context, refreshToken string) (*model.AuthPayload, error) {
	_, ok := ctx.Value(contextKey.JwtErrorKey).(error)

	if ok {
		return nil, fmt.Errorf("user unauthenticated")
	}

	userId, ok := ctx.Value(contextKey.UserIDKey).(string)

	if !ok {
		return nil, fmt.Errorf("user unauthenticated")
	}

	token, refreshToken, err := auth.RefreshToken(userId, refreshToken)

	if err != nil {
		return nil, err
	}

	authPayload := &model.AuthPayload{
		Token:        token,
		RefreshToken: refreshToken,
	}

	return authPayload, nil
}

// UpdateUser is the resolver for the updateUser field.
func (r *mutationResolver) UpdateUser(ctx context.Context, input model.UpdateUserInput) (*model.UpdateUserPayload, error) {
	_, ok := ctx.Value(contextKey.JwtErrorKey).(error)

	if ok {
		return nil, fmt.Errorf("user unauthenticated")
	}

	userId, ok := ctx.Value(contextKey.UserIDKey).(string)

	if !ok {
		return nil, fmt.Errorf("user unauthenticated")
	}

	if input.CurrentPassword == "" {
		return nil, fmt.Errorf("current password must be provided")
	}

	// Ensure at least one of newEmail, newUsername, newPassword is provided
	if input.NewEmail == nil && input.NewUsername == nil && input.NewPassword == nil {
		return nil, fmt.Errorf("at least one of new email, new username or new password must be provided")
	}

	var newUsernameStr, newEmailStr, newPasswordStr string

	if input.NewUsername != nil {
		if len(*input.NewUsername) <= 1 {
			return nil, fmt.Errorf("username must be at least 2 characters")
		}
		newUsernameStr = *input.NewUsername
	}

	if input.NewEmail != nil {
		if !utils.ValidateEmail(*input.NewEmail) {
			return nil, fmt.Errorf("invalid email format")
		}
		newEmailStr = *input.NewEmail
	}

	if input.NewPassword != nil {
		if !utils.ValidatePassword(*input.NewPassword) {
			return nil, fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
		}
		newPasswordStr = *input.NewPassword
	}

	_, emailConfirmed, err := auth.UpdateUser(userId, input.CurrentPassword, newUsernameStr, newEmailStr, newPasswordStr)

	if err != nil {
		return nil, err
	}

	updateUserPayload := &model.UpdateUserPayload{
		EmailConfirmed: emailConfirmed,
	}

	return updateUserPayload, nil
}

// DeleteUser is the resolver for the deleteUser field.
func (r *mutationResolver) DeleteUser(ctx context.Context) (bool, error) {
	_, ok := ctx.Value(contextKey.JwtErrorKey).(error)

	if ok {
		return false, fmt.Errorf("user unauthenticated")
	}

	userId, ok := ctx.Value(contextKey.UserIDKey).(string)

	if !ok {
		return false, fmt.Errorf("user unauthenticated")
	}

	_, err := auth.DeleteUser(userId)

	if err != nil {
		return false, err
	}

	return true, nil
}

// CheckCredentials is the resolver for the checkCredentials field.
func (r *mutationResolver) CheckCredentials(ctx context.Context, input model.UserInput) (bool, error) {
	if len(input.Username) < 2 {
		return false, fmt.Errorf("username must be at least 2 characters")
	}

	if !utils.ValidateEmail(input.Email) {
		return false, fmt.Errorf("invalid email format")
	}

	return auth.CheckCredentials(input.Username, input.Email, input.Password)
}

// ResetPassword is the resolver for the resetPassword field.
func (r *mutationResolver) ResetPassword(ctx context.Context, input model.ResetPasswordInput) (bool, error) {
	if !utils.ValidateEmail(input.Email) {
		return false, fmt.Errorf("invalid email format")
	}

	err := auth.ResetPassword(input.Email, input.NewPassword)

	if err != nil {
		return false, err
	}

	return true, nil
}

// ConfirmEmail is the resolver for the confirmEmail field.
func (r *mutationResolver) ConfirmEmail(ctx context.Context, confirmationToken string) (bool, error) {
	_, ok := ctx.Value(contextKey.JwtErrorKey).(error)

	if ok {
		return false, fmt.Errorf("user unauthenticated")
	}

	userId, ok := ctx.Value(contextKey.UserIDKey).(string)

	if !ok {
		return false, fmt.Errorf("user unauthenticated")
	}

	if confirmationToken == "" {
		return false, fmt.Errorf("invalid confirmation token")
	}

	err := auth.ConfirmEmail(userId, confirmationToken)

	if err != nil {
		return false, err
	}

	return true, nil
}

// User is the resolver for the user field.
func (r *queryResolver) User(ctx context.Context, id string) (*model.User, error) {
	panic(fmt.Errorf("not implemented: User - user"))
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }