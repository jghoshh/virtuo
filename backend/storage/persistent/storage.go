package storage

import (
	"context"
	"fmt"
	"github.com/jghoshh/virtuo/backend/models"
)

// DeleteResult represents the result of a deletion operation in MongoDB,
// specifically the count of documents deleted.
type DeleteResult struct {
	DeletedCount int64
}

// UpdateResult represents the result of an update operation in MongoDB,
// specifically the count of documents matched and modified.
type UpdateResult struct {
	MatchedCount  int64
	ModifiedCount int64
}

// StorageInterface defines the set of methods that any persistent storage 
// backend needs to implement.
type StorageInterface interface {
	// Establishes a connection to the storage backend.
	Connect(dbName, uri string) error
	// Disconnects from the storage backend.
	Disconnect() error
	// Adds a new user to the storage backend.
	AddUser(ctx context.Context, user *models.User) (*models.User, error)
	// Finds a user in the storage backend using a filter.
	FindUser(ctx context.Context, filter interface{}) (*models.User, error)
	// Updates an existing user in the storage backend using a filter and update instructions.
	UpdateUser(ctx context.Context, filter interface{}, update interface{}) (*models.User, error)
	// Deletes a user in the storage backend using a filter.
	DeleteUser(ctx context.Context, filter interface{}) (*DeleteResult, error) 
	// Returns the count of users in the storage backend using a filter.
	UserCount(ctx context.Context, filter interface{}) (int64, error)
	// Adds a new habit to the storage backend.
	AddHabit(ctx context.Context, habit *models.Habit) (*models.Habit, error)
	// Finds habits in the storage backend using a filter.
	FindHabitsByParameter(ctx context.Context, filter interface{}) ([]models.Habit, error)
	// Updates an existing habit in the storage backend using a filter and update instructions.
	UpdateHabit(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error)
	// Deletes a habit in the storage backend using a filter.
	DeleteHabit(ctx context.Context, filter interface{}) (*DeleteResult, error)
	// Adds a new confirmation to the storage backend.
	AddConfirmation(ctx context.Context, confirmation *models.Confirmation) (*models.Confirmation, error)
	// Finds a confirmation in the storage backend using a filter.
	FindConfirmation(ctx context.Context, filter interface{}) (*models.Confirmation, error)
	// Updates an existing confirmation in the storage backend using a filter and update instructions.
	UpdateConfirmation(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error)
	// Deletes a confirmation in the storage backend using a filter.
	DeleteConfirmation(ctx context.Context, filter interface{}) (*DeleteResult, error)
}

// NewStorage creates a new StorageInterface with a MongoDB backend,
// using the provided URI to connect to the MongoDB server.
func NewStorage(dbName, uri string) (StorageInterface, error) {
	storage := NewMongoStorage()
	err := storage.Connect(dbName, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	return storage, nil
}