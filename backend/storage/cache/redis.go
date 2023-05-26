package storage

import (
	"fmt"
	"encoding/json"
	"github.com/go-redis/redis/v8"
	"context"
	"time"
)

// RedisCache is a struct representing a Redis cache instance. 
// It provides an interface to perform CRUD operations on the cache instance.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache creates a new instance of RedisCache.
// This function doesn't establish a connection to the Redis server.
// To connect to the server, use the Connect method of the returned RedisCache instance.
func NewRedisCache() *RedisCache {
	return &RedisCache{}
}

// Connect establishes a connection to the Redis backend.
func (r *RedisCache) Connect(redisURL string) error {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		panic(err)
	}
	
	r.client = redis.NewClient(opt)

	_, err = r.client.Ping(context.Background()).Result()
	return err
}

// Disconnect closes the connection to the Redis server.
func (r *RedisCache) Disconnect() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Set sets a key-value pair in the Redis cache.
// It marshals the value into a JSON string before storing it.
// The key-value pair is set to expire after 72 hours.
func (r *RedisCache) Set(ctx context.Context, key string, value interface{}) error {
	marshaledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	// Set the key-value pair in Redis to expire after 72 hours.
	return r.client.Set(ctx, key, marshaledValue, time.Hour * 72).Err()
}

// Get retrieves the value of a given key from the Redis cache.
// It unmarshals the retrieved JSON string into an interface{}.
// If the key is not found, it returns a redis.Nil error.
func (r *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	value, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("key does not exist")
	} else if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Clear removes all keys from the currently selected database in the Redis cache.
func (r *RedisCache) Clear(ctx context.Context) error {
    return r.client.FlushDB(ctx).Err()
}