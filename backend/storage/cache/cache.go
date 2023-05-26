package storage

import (
	"context"
	"fmt"
)

// CacheInterface defines the set of methods that need to be implemented to 
// be used as a cache storage. 
type CacheInterface interface {
	Connect(url string) error
	Disconnect() error
	Set(ctx context.Context, key string, value interface{}) error
	Get(ctx context.Context, key string) (interface{}, error)
	Clear(ctx context.Context) error

}

// NewCache creates a new CacheInterface with a Redis backend.
// It connects to the provided address, and returns the cache instance or 
// an error if the connection failed.
func NewCache(url string) (CacheInterface, error) {
	cache := NewRedisCache() // Currently, the redis cache is hardcoded.
	err := cache.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	return cache, nil
}