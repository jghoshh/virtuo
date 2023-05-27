package server

import (
	"log"
	"net/http"
    "net/url"
	"os"
	"time"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"github.com/form3tech-oss/jwt-go"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/jghoshh/virtuo/backend/graph"
    "github.com/jghoshh/virtuo/backend/server/context_key"
	"fmt"
	"strings"
	"context"
)

// jwtMiddleware is a middleware function that performs JWT validation.
//
// It accepts two arguments:
// - signingKey: A key used for validating the JWT signature.
// - next: The next http.Handler to be executed once the middleware has done its job.
//
// This function reads the JWT from the Authorization header of the HTTP request. If a JWT is present,
// it verifies the token's signature and checks if it has expired. If the JWT is valid, the function
// injects the user's ID extracted from the JWT into the request's context under the contextKey.UserIDKey.
//
// If the JWT has expired but the claims can still be extracted, the function also injects the user's ID
// into the request's context. In case of any error during the JWT parsing, the function injects the error
// into the request's context under the contextKey.JwtErrorKey.
//
// The function does not stop the HTTP request processing and always calls the next http.Handler regardless
// of whether a JWT was present and valid, or any error occurred. Thus, it's up to the next handlers
// to interpret the data in the request's context and react accordingly.
func jwtMiddleware(signingKey string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader != "" {
            log.Println("Authorization header is present")
            splitToken := strings.Split(authHeader, "Bearer ")
            if len(splitToken) == 2 {
                log.Println("Token found in Authorization header")
                token, err := jwt.Parse(splitToken[1], func(token *jwt.Token) (interface{}, error) {
                    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
                    }
                    return []byte(signingKey), nil
                })
                if err != nil {
                    log.Println("Error occurred while parsing JWT token:", err)
                    if err, ok := err.(*jwt.ValidationError); ok && err.Errors == jwt.ValidationErrorExpired {
                        log.Println("Token has expired")
                        if claims, ok := token.Claims.(jwt.MapClaims); ok {
                            log.Println("Claims found in expired token")
                            ctx := context.WithValue(r.Context(), contextKey.UserIDKey, claims["id"])
                            r = r.WithContext(ctx)
                        }
                    } else {
                        log.Println("JWT token validation error:", err)
                        ctx := context.WithValue(r.Context(), contextKey.JwtErrorKey, err)
                        r = r.WithContext(ctx)
                    }
                } else if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                    log.Println("Valid token with claims")
                    ctx := context.WithValue(r.Context(), contextKey.UserIDKey, claims["id"])
                    r = r.WithContext(ctx)
                }
            }
        } else {
            log.Println("No Authorization header present")
        }
        next.ServeHTTP(w, r)
    })
}

// recoveryMiddleware is a middleware function that recovers from panics and provides a generic error message to the client.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %s\n", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Start initializes and starts the GraphQL server. Runs on localhost:8080 by default.
// The function requires a serverURL (the URL where the server must be deployed) and the JWT signing key.
func Start(serverURL, signingKey string) {
    // Initialize a new router
    r := mux.NewRouter()

    // Initialize the GraphQL server
    srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}}))

    // Set up the GraphQL endpoint with JWT middleware and recovery middleware
    r.Handle("/graphql", recoveryMiddleware(jwtMiddleware(signingKey, srv)))

    // Set up the GraphQL Playground endpoint
    r.Handle("/", playground.Handler("GraphQL playground", "/graphql"))

    // Apply the CORS middleware to the router
    corsOrigins := handlers.AllowedOrigins([]string{"*"})
    corsMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"})
    corsHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})

    // Wrap the router with the CORS middleware
    corsRouter := handlers.CORS(corsOrigins, corsMethods, corsHeaders)(r)

    // Apply the logging middleware
    loggingRouter := handlers.LoggingHandler(os.Stdout, corsRouter)

    // Parsing the server url
    u, err := url.Parse(serverURL)
    if err != nil {
		panic(err)
	}

    // Start the server
    server := &http.Server{
        Handler:      loggingRouter,
        Addr:         u.Host,
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    // Setting up the logging middleware
    log.Fatal(server.ListenAndServe())
}