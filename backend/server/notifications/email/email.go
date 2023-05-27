package email

import (
	"fmt"
	"net/smtp"
)

// smtpServer is a global variable that stores a string that represents the address of the SMTP server which is used to send emails.
var smtpServer string

// auth is an global variable thhat holds a smtp.Auth struct that stores the authentication data needed to connect to the SMTP server.
// It is initialized by the smtp.PlainAuth function, which takes the username and password of the email sender.
var auth smtp.Auth

// fromEmail is global variable that stores a string that represents the email address of the sender. This is used as the "From" address in the emails that are sent.
var fromEmail string

// InitEmailService is a function that initializes the email service by establishing an SMTP connection
// to a specified email server. 
// It accepts two arguments:
// - sender: A string containing the email address of the sender. This is used as the "From" address in the emails that are sent.
// - password: A string containing the password of the sender's email account.
//
// This function performs two main tasks:
// It sets the SMTP server address and the sender's email address,
// and establishes an SMTP connection using the smtp.PlainAuth function with the sender's email and password.
// It then tries to dial to the SMTP server to check if the connection is successful.
//
// If successful in establishing a connection, the function returns true.
// If an error occurs during any step of the process, it returns false and the error.
func InitEmailService(sender, password string) (bool, error) {
	smtpServer = "smtp.gmail.com:587"
	fromEmail = sender

	auth = smtp.PlainAuth(
		"",
		sender,
		password,
		"smtp.gmail.com",
	)

	c, err := smtp.Dial(smtpServer)
	if err != nil {
		return false, fmt.Errorf("cannot connect to the SMTP server: %v", err)
	}

	err = c.Close()
	if err != nil {
		return false, fmt.Errorf("cannot close the SMTP connection: %v", err)
	}

	return true, nil
}

// SendEmail is a function that sends an email to a specified recipient with a given token.
// It accepts two arguments:
// - to: A string containing the email address of the recipient.
// - token: A string containing the token to be sent to the recipient.
//
// This function performs several tasks:
// It sets the headers for the email, creates an HTML email body containing the token,
// and then sends the email using the established SMTP server connection.
//
// The function returns an error if there was a problem with any step of the process.
func SendEmail(to, token string) error {
	fmt.Println("sending email")

	headers := make(map[string]string)
	headers["From"] = fromEmail
	headers["To"] = to
	headers["Subject"] = "Your Confirmation Token"
	headers["MIME-version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	body := `
	<html>
		<head>
			<style>
				@import url('https://fonts.googleapis.com/css2?family=Lato:wght@400;700&display=swap');
				body {
					font-family: 'Lato', sans-serif;
					margin: 0;
					padding: 0;
				}
				.container {
					max-width: 600px;
					margin: 0 auto;
					padding: 10px;
					border-radius: 4px;
				}
				h1 {
				}
				p {
					line-height: 1.6;
				}
				code {
					padding: 2px 4px;
					border-radius: 3px;
					font-family: monospace;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Hello,</h1>
				<p>Here is your confirmation token: <strong>` + token + `</strong></p>
				<p>Please, run the <code>"confirm"</code> command in your command line, and insert the token above, mind the case sensitivity.</p>
			</div>
		</body>
	</html>
	`
	message += "\r\n" + body

	err := smtp.SendMail(
		smtpServer,
		auth,
		fromEmail,
		[]string{to},
		[]byte(message),
	)

	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	fmt.Println("email sent")
	return nil
}