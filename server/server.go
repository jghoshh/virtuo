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
	"github.com/jghoshh/virtuo/graph"
    "github.com/jghoshh/virtuo/contextKey"
	"fmt"
	"strings"
	"context"
)

func jwtMiddleware(signingKey string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader != "" {
            fmt.Println("Authorization header is present")
            splitToken := strings.Split(authHeader, "Bearer ")
            if len(splitToken) == 2 {
                fmt.Println("Token found in Authorization header")
                token, err := jwt.Parse(splitToken[1], func(token *jwt.Token) (interface{}, error) {
                    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
                    }
                    return []byte(signingKey), nil
                })
                if err != nil {
                    fmt.Println("Error occurred while parsing JWT token:", err)
                    if err, ok := err.(*jwt.ValidationError); ok && err.Errors == jwt.ValidationErrorExpired {
                        fmt.Println("Token has expired")
                        if claims, ok := token.Claims.(jwt.MapClaims); ok {
                            fmt.Println("Claims found in expired token")
                            ctx := context.WithValue(r.Context(), contextKey.UserIDKey, claims["id"])
                            r = r.WithContext(ctx)
                        }
                    } else {
                        fmt.Println("JWT token validation error:", err)
                        ctx := context.WithValue(r.Context(), contextKey.JwtErrorKey, err)
                        r = r.WithContext(ctx)
                    }
                } else if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                    fmt.Println("Valid token with claims")
                    ctx := context.WithValue(r.Context(), contextKey.UserIDKey, claims["id"])
                    r = r.WithContext(ctx)
                }
            }
        } else {
            fmt.Println("No Authorization header present")
        }
        next.ServeHTTP(w, r)
    })
}

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
    rawURL := "http://localhost:8080"
    u, err := url.Parse(rawURL)
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

    log.Fatal(server.ListenAndServe())
}
