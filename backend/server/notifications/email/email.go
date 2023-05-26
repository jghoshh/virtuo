package email

import (
	"fmt"
	"net/smtp"
)

// smtpServer is a string that stores the address of the SMTP server which is used to send emails.
var smtpServer string

// auth is an smtp.Auth struct that stores the authentication data needed to connect to the SMTP server.
// It is initialized by the smtp.PlainAuth function, which takes the username and password of the email sender.
var auth smtp.Auth

// fromEmail is a string that stores the email address of the sender. This is used as the "From" address in the emails that are sent.
var fromEmail string

// InitEmailService initializes the email service by establishing an SMTP connection
// to a specified email server. It takes the email sender's address and password as
// input parameters. Returns a boolean indicating the success of the operation and
// an error if any occurred during the process.
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

// SendEmail sends an email to the specified recipient with a given token.
// It creates an email with a confirmation token embedded in an HTML template,
// and sends it using the SMTP server connection established by InitEmailService.
// Returns an error if any occurred during the process.
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