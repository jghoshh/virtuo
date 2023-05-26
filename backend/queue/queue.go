package queue

import (
	"github.com/streadway/amqp"
	"log"
	"context"
	"time"
	"sync"
)

// Producer interface provides the Publish method to publish messages to RabbitMQ. 
// Publish sends a message body as a byte array to RabbitMQ. 
// Returns an error if there was a problem.
type Producer interface {
	Publish(body []byte) error  // Publish allows to publish a message in RabbitMQ.
}

// Consumer interface provides the Consume method to consume messages from RabbitMQ.
// Consume listens to messages from RabbitMQ and handles the message stream.
// Returns the stream of RabbitMQ Delivery and an error if there was a problem.
type Consumer interface {
	Consume(ctx context.Context) (<-chan amqp.Delivery, error)  // Consume listens to messages from RabbitMQ.
}

// ProducerFactory interface provides the CreateProducer method to instantiate new producers.
// CreateProducer uses a RabbitMQ connection, channel and queue details to create a new Producer.
// Returns the newly created Producer or an error.
type ProducerFactory interface {
	CreateProducer(conn *amqp.Connection, ch *amqp.Channel, queue *amqp.Queue) (Producer, error)
}

// ConsumerFactory interface provides the CreateConsumer method to instantiate new consumers.
// CreateConsumer uses a RabbitMQ connection, channel and queue details to create a new Consumer.
// Returns the newly created Consumer or an error.
type ConsumerFactory interface {
	CreateConsumer(conn *amqp.Connection, ch *amqp.Channel, queue *amqp.Queue) (Consumer, error)
}

// Queue struct holds slices of Producers and Consumers which can be used to send and consume messages.
type Queue struct {
	Producers []Producer
	Consumers []Consumer
}

// connect function establishes a connection to RabbitMQ and opens a new channel.
// The function listens for closure of connection and logs any closure error.
// Returns the RabbitMQ connection, channel, and an error if there was a problem.
func connect(url string) (*amqp.Connection, *amqp.Channel, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		return nil, nil, err
	}

	if err = ch.Confirm(false); err != nil {
		return nil, nil, err
	}

	notifyClose := make(chan *amqp.Error)
	conn.NotifyClose(notifyClose)

	go func() {
		err := <-notifyClose
		if err != nil {
			log.Fatalf("RabbitMQ connection closed: %v", err)
		}
	}()

	return conn, ch, nil
}

// InitQueue function initializes a Queue with producers and consumers.
// It first establishes a connection to the RabbitMQ instance using the provided URL.
// Upon a successful connection, it declares a new queue using the provided queue name.
// The queue is configured to be durable, not auto-deleted when unused, not exclusive, and doesn't wait for server acknowledgment.
// After declaring the queue, it uses the provided producer and consumer factories to create producers and consumers for the queue.
// These producers and consumers are added to the Queue struct, which is then returned.
func InitQueue(url string, queueName string, prodFactories []ProducerFactory, consFactories []ConsumerFactory) *Queue {
	conn, ch, err := connect(url)
	if err != nil {
		log.Fatalf("error connecting to RabbitMQ: %v", err)
	}

	var producers []Producer
	var consumers []Consumer

	queue, err := ch.QueueDeclare(
		queueName, 
		true,      // Durable
		false,     // Delete when unused
		false,     // Exclusive
		false,     // No-wait
		nil,       // Arguments
	)
	if err != nil {
		log.Fatalf("error declaring queue: %v", err)
	}

	for _, prodFactory := range prodFactories {
		producer, err := prodFactory.CreateProducer(conn, ch, &queue) 
		if err != nil {
			log.Fatalf("error creating producer: %v", err)
		}
		producers = append(producers, producer)
	}

	for _, consFactory := range consFactories {
		consumer, err := consFactory.CreateConsumer(conn, ch, &queue)
		if err != nil {
			log.Fatalf("error creating consumer: %v", err)
		}
		consumers = append(consumers, consumer)
	}

	return &Queue{
		Producers: producers,
		Consumers: consumers,
	}
}


// StartConsumers is a method on the Queue struct that starts all consumers in the queue.
// Each consumer is started in its own goroutine, allowing them to process messages independently and concurrently.
// It takes in a context as the first parameter, which allows the caller to control the lifetime of the consumers.
// If the context is cancelled (say, by the caller or due to an error), the consumers stop consuming messages and the function will return.
// As an optional second parameter, the function accepts a duration. If provided, a context with timeout is created.
// This means that the consumers will stop after the specified duration, even if the original context hasn't been cancelled.
// The returned cancel function can be used by the caller to stop the consumers before the context or timeout ends, and the 
// returned WaitGroup can be used to wait for all consumers to finish.
func (q *Queue) StartConsumers(ctx context.Context, runFor ...time.Duration) (context.CancelFunc, *sync.WaitGroup, error) {
	if len(runFor) > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, runFor[0])

		// automatically cancel the context when the timeout is reached
		go func() {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				cancel()
			}
		}()
		return cancel, nil, ctx.Err()
	}

	var wg sync.WaitGroup

	for _, consumer := range q.Consumers {
		wg.Add(1)

		go func(c Consumer) {
			defer wg.Done()

			if _, err := c.Consume(ctx); err != nil {
				log.Printf("Error starting consumer: %v", err)
			}
		}(consumer)
	}

	return nil, &wg, nil
}