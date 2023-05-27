package queue

import (
	"context"
	"encoding/json"
	"github.com/streadway/amqp"
	"github.com/jghoshh/virtuo/backend/server/notifications/email"
	"github.com/jghoshh/virtuo/backend/storage/cache"
	"log"
	"fmt"
	"errors"
)

// globalCount is a global variable used in the round robin algorithm to assign producers to each email message.
var globalCount int

// EmailProducerFactory is a struct for creating new EmailProducer instances
type EmailProducerFactory struct{}

// EmailConsumerFactory is a struct for creating new EmailConsumer instances
// It contains a Cache which is an interface to the cache service.
type EmailConsumerFactory struct {
	Cache storage.CacheInterface
}

// EmailProducer is a struct for managing the connection, channel, and queue of the AMQP message producer for emails
type EmailProducer struct {
	conn    *amqp.Connection // the connection to the AMQP broker
	channel *amqp.Channel    // the channel used for publishing messages
	queue   *amqp.Queue       // the queue from which messages will be sent
}

// EmailConsumer is a struct for managing the connection, channel, queue and cache of the AMQP message consumer for emails
type EmailConsumer struct {
	conn    *amqp.Connection      // the connection to the AMQP broker
	channel *amqp.Channel         // the channel used for consuming messages
	queue   *amqp.Queue            // the queue from which messages will be consumed
	cache   storage.CacheInterface // the cache for checking if a message has been processed
}

// EmailMessage is a struct for the content of email messages
type EmailMessage struct {
	Id    string `json:"id"`    // the id of the message
	Token string `json:"token"` // the email confirmation token
	To    string `json:"to"`    // the recipient of the message
}

// CreateProducer is a method on EmailProducerFactory for creating a new instance of EmailProducer.
// It accepts three arguments:
// - conn: A pointer to an AMQP connection.
// - ch: A pointer to an AMQP channel.
// - queue: A pointer to an AMQP queue.
//
// This method performs the task of instantiating a new EmailProducer with the given connection, channel, and queue.
// The function returns a new instance of EmailProducer and an error. In the current implementation, the error is always nil.
func (f *EmailProducerFactory) CreateProducer(conn *amqp.Connection, ch *amqp.Channel, queue *amqp.Queue) (Producer, error) {
	// We always nil for error for now. If in the future we needed to do some setup before returning the producer, 
	// we could employ error checking there.
	return &EmailProducer{
		conn: conn,
		channel: ch,
		queue: queue,
	}, nil
}

// CreateConsumer is a method on EmailConsumerFactory for creating a new instance of EmailConsumer.
// It accepts three arguments:
// - conn: A pointer to an AMQP connection.
// - ch: A pointer to an AMQP channel.
// - queue: A pointer to an AMQP queue.
//
// This method performs the task of instantiating a new EmailConsumer with the given connection, channel, queue, and cache.
// The function returns a new instance of EmailConsumer and an error. In the current implementation, the error is always nil.
func (f *EmailConsumerFactory) CreateConsumer(conn *amqp.Connection, ch *amqp.Channel, queue *amqp.Queue) (Consumer, error) {
	// We always nil for error for now. If in the future we needed to do some setup before returning the producer, 
	// we could employ error checking there.
    return &EmailConsumer{
        conn: conn,
        channel: ch,
        queue: queue,
        cache: f.Cache,
    }, nil
}

// Publish is a method on EmailProducer for publishing a message to the AMQP queue.
// It accepts a single argument:
// - body: A byte array containing the message to be published.
//
// This method performs the task of publishing the given message to the queue.
// The function returns an error if there was a problem with publishing the message.
func (ep *EmailProducer) Publish(body []byte) error {
	err := ep.channel.Publish(
		"",             // exchange
		ep.queue.Name,  // routing key
		false,          // mandatory
		false,          // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		})
	if err != nil {
		return fmt.Errorf("failed to publish a message: %w", err)
	}

	return nil
}

// Consume is a method on EmailConsumer for consuming messages from the AMQP queue.
// It accepts a single argument:
// - ctx: The context within which the method is being called.
//
// This method performs several tasks. It sets up a consumer on the queue and then launches a goroutine that continuously reads from the queue.
// It handles each message by unmarshalling it, checking its processed state from the cache, and then either processing it (sending an email) or discarding it.
// The function returns a channel of deliveries from the queue and an error if there was a problem with setting up the consumer.
func (ec *EmailConsumer) Consume(ctx context.Context) (<-chan amqp.Delivery, error) {
	msgs, err := ec.channel.Consume(
		ec.queue.Name,
		"",
		false, 
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Deploy the consumer worker to read messages from the queue. 
	go func() {
		for {
			select {
			case d, ok := <-msgs:

				if !ok {
					return
				}

				message := &EmailMessage{}
				if err := json.Unmarshal(d.Body, message); err != nil {
					log.Printf("failed to unmarshal email message: %v", err)
					d.Nack(false, true) // requeue the message in case of transient error.
					continue
				}
				
				// Fetch processed state from cache
				processed, err := ec.cache.Get(ctx, "email_"+message.Id)
				if err != nil {
					// Ignore cache misses, handle other errors
					if err.Error() != "key does not exist" {
						log.Printf("error checking cache: %v", err)
						d.Nack(false, true) // requeue the message in case of transient error.
						continue
					}
				}

				if processed != nil {
					d.Ack(false)
					continue
				}

				// At this point, we know the message has not been processed, so we can send the email.
				if err := email.SendEmail(message.To, message.Token); err != nil {
					log.Printf("failed to send email: %v", err)
					d.Nack(false, true) // requeue the message in case of transient error.
				} else {
					d.Ack(false)
					if err := ec.cache.Set(ctx, "email_"+message.Id, true); err != nil {
						log.Printf("failed to set key in cache: %v", err)
					}
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return msgs, nil
}

// BuildEmailQueue is a function that initializes a new Queue for handling email messages.
// It accepts four arguments:
// - rabbitMQURL: A string containing the URL of the RabbitMQ server.
// - numProducers: An integer indicating the number of producers to create.
// - numConsumers: An integer indicating the number of consumers to create.
// - emailCache: A CacheInterface instance to be used for caching email messages.
//
// This function performs several tasks. It creates the specified number of EmailProducer and EmailConsumer instances using factories and initializes a new Queue with the created producers and consumers.
// The function returns the initialized Queue.
func BuildEmailQueue(rabbitMQURL string, numProducers int, numConsumers int, emailCache storage.CacheInterface) *Queue {

	// Producer factories
	prodFactories := make([]ProducerFactory, numProducers)
	for i := 0; i < numProducers; i++ {
		prodFactories[i] = &EmailProducerFactory{}
	}

	// Consumer factories
	consFactories := make([]ConsumerFactory, numConsumers)
	for i := 0; i < numConsumers; i++ {
		consFactories[i] = &EmailConsumerFactory{Cache: emailCache}
	}

	// Initialize the queue
	queue := InitQueue(rabbitMQURL, "emailQueue", prodFactories, consFactories)
	return queue
}

// InitEmailCache is a function that initializes the cache storage for confirmation email messages.
// It accepts one argument:
// - url: A string containing the URL of the cache server.
//
// This function performs the task of creating a new cache with the given URL.
// The function returns a CacheInterface object that can be used to communicate with the cache in the backend.
func InitEmailCache(url string) storage.CacheInterface {
	c, err := storage.NewCache(url)
	if err != nil {
		log.Fatalf("Error connecting to cache: %v", err)
	}
	return c
}

// ProcessEmail is a function that takes an EmailMessage and a Queue of producers,
// serializes the email message to JSON, and then publishes it onto the queue using one of the producers in a round-robin manner.
// It accepts two arguments:
// - emailMsg: A pointer to the EmailMessage to be processed.
// - emailQueue: A pointer to the Queue to which the email message is to be published.
//
// This function performs several tasks. It serializes the email message, selects a producer from the queue in a round-robin manner, and then publishes the serialized message to the queue.
// The function returns an error if there was a problem with any step of the process.
func ProcessEmail(emailMsg *EmailMessage, emailQueue *Queue) error {

	body, err := json.Marshal(emailMsg)
	if err != nil {
		return errors.New("failed to marshal email message: " + err.Error())
	}

	producerCount := len(emailQueue.Producers)
	if producerCount == 0 {
		return errors.New("no producers available")
	}

	producer := emailQueue.Producers[globalCount%producerCount]
	globalCount++

	if err := producer.Publish(body); err != nil {
		return errors.New("failed to publish email message: " + err.Error())
	}

	return nil
}