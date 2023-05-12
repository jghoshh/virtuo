package storage

import (
	"context"
	"fmt"
	"github.com/jghoshh/virtuo/models"
)

type DeleteResult struct {
	DeletedCount int64
}

type StorageInterface interface {
	Connect(uri string) error
	Disconnect() error
	// User
	AddUser(ctx context.Context, user *models.User) (*models.User, error)
	FindUser(ctx context.Context, filter interface{}) (*models.User, error)
	UpdateUser(ctx context.Context, filter interface{}, update interface{}) (*models.User, error)
	DeleteUser(ctx context.Context, filter interface{}) (*DeleteResult, error) 
	UserCount(ctx context.Context, filter interface{}) (int64, error)
}

func NewStorage(uri string) (StorageInterface, error) {
	storage := NewMongoStorage()
	err := storage.Connect(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	return storage, nil
}