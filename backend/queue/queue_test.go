package queue

import (
	"context"
	"testing"
	"fmt"
	"log"
	"os"
	"sync"
	"encoding/json"
	"github.com/jghoshh/virtuo/backend/server/notifications/email"
	"github.com/joho/godotenv"
	"time"
)

var q *Queue

func TestMain(m *testing.M) {
	// Load environment variables.
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	smtpEmail := os.Getenv("GOOGLE_EMAIL")
	smtpPassword := os.Getenv("GOOGLE_PASS")
	redisUrl := os.Getenv("REDIS_URL")
	rabbitMQURL := os.Getenv("RABBITMQ_URL")

	email.InitEmailService(smtpEmail, smtpPassword)
	c := InitEmailCache(redisUrl)

	// Clear the cache before each run
	err = c.Clear(context.Background())
	if err != nil {
		log.Fatalf("Error clearing cache: %v", err)
	}

	// Initialize the queue with BuildEmailQueue
	q = BuildEmailQueue(rabbitMQURL, 1, 3, c) 
	fmt.Println(q.Producers)

	// Create a context that we'll use to stop the consumers
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a WaitGroup to synchronize the consumers
	var wg sync.WaitGroup

	// Start consumers
	for _, consumer := range q.Consumers {
		fmt.Println("Starting consumer")

		wg.Add(1)

        go func(c Consumer) {
            defer wg.Done() 

            _, err := c.Consume(ctx)
            fmt.Println("Consuming")
            if err != nil {
                log.Fatalf("Error starting consumer: %v", err)
            }

			<-ctx.Done()
			fmt.Println("context done")

        }(consumer)
	}

	exitVal := m.Run()

	fmt.Println("Waiting")
	wg.Wait()

	fmt.Println("Exiting")
	os.Exit(exitVal)
}

func TestEmailPublish(t *testing.T) {

	testEmail1 := "test1@gmail.com"
	testEmail2 := "test2@gmail.com"

    // Prepare the first email message for twentyfivewaves
    emailMsg1 := &EmailMessage{
        Id:    "121029301293",
        Token: "token_124",
        To:    testEmail1,
    }

    // Prepare the second email message for twentyfivewaves
    emailMsg2 := &EmailMessage{
        Id:    "i121029301294",
        Token: "token_125",
        To:    testEmail1,
    }

    // Prepare the first email message for volace01
    emailMsg3 := &EmailMessage{
        Id:    "434343433",
        Token: "token_546",
        To:     testEmail2,
    }

    // Prepare the second email message for volace01
    emailMsg4 := &EmailMessage{
        Id:    "434343434",
        Token: "token_547",
        To:     testEmail2,
    }

    // Prepare the list of email messages
    emailMessages := []*EmailMessage{emailMsg1, emailMsg2, emailMsg3, emailMsg4}

	producerCount := len(q.Producers)
	for i, emailMsg := range emailMessages {
		body, err := json.Marshal(emailMsg)
		if err != nil {
			t.Fatalf("Error marshaling email message: %v", err)
		}

		// Choose the producer in a round-robin fashion
		producer := q.Producers[i % producerCount]

		err = producer.Publish(body)
		if err != nil {
			t.Fatalf("Error publishing email message: %v", err)
		}
	}
}
