package cmd

import (
	"strings"
	ishell "github.com/abiosoft/ishell"
	"github.com/common-nighthawk/go-figure"
	"github.com/jghoshh/virtuo/frontend/client"
	"github.com/jghoshh/virtuo/lib/utils"
	"fmt"
	"os"
)

// guestCommands is a slice of Command structures containing commands that are available to users who have not logged in.
var guestCommands []Command

// userCommands is a slice of Command structures containing commands that are available only to logged in users.
var userCommands []Command

// commonCommands is a slice of Command structures containing commands that are available to all users, regardless of their login status.
var commonCommands []Command

// loggedIn is a boolean variable that indicates whether a user is currently logged in. It is true when a user is logged in and false otherwise.
var loggedIn bool

// shell represents an instance of the interactive shell used for this application. Users can interact with the application by executing commands on this shell.
var shell *ishell.Shell

// confirmedEmail is a boolean variable that indicates whether a user has confirmed their email. It is true when the email is confirmed and false otherwise.
var confirmedEmail bool

// The Command struct defines a user command in the system. Each command has a Name, a Desc (short for description), and a Func (the function to execute when the command is called).
type Command struct {
	Name string // Name is the name of the command.
	Desc string // Desc is a short description of what the command does.
	Func func(c *ishell.Context) // Func is the function that is executed when the command is invoked.
}

// InitAuthCmd is a function that initializes the authentication commands.
// It initializes the shell and sets up the commands for guest and user scenarios.
func InitAuthCmd() { 

	// Initialize shell
	shell = ishell.New()

	// Define the commands available to a guest user (not signed in)
	guestCommands = []Command{
		{
			Name: "signin",
			Desc: "Sign in to your account",
			Func: func(c *ishell.Context) {
				var username, password string
				for {
					c.Print("Enter Username: ")
					username = c.ReadLine()
	
					if len(username) > 1 {
						break
					}
					c.Println("Username must be longer than 1 character.")
				}
	
				for {
					c.Print("Enter Password: ")
					password = c.ReadPassword()
	
					if len(password) > 0 {
						break
					}
					c.Println("Password cannot be empty.")
				}
	
				_, _, err := client.SignIn(username, password)
				if err != nil {
					utils.PrintError(err.Error())
					return
				}
				loggedIn = true
				c.Println("Welcome, you are now signed in.")
				for _, command := range guestCommands {
					shell.DeleteCmd(command.Name)
				}
				addCommands(shell, userCommands)
			},
		},
		{
			Name: "signup",
			Desc: "Sign up for a new account",
			Func: func(c *ishell.Context) {
				var username, email, password string
				for {
					c.Print("Enter Username: ")
					username = c.ReadLine()
	
					if len(username) > 1 {
						break
					}
					c.Println("Username must be longer than 1 character.")
				}
	
				for {
					c.Print("Enter Email: ")
					email = c.ReadLine()
	
					if utils.ValidateEmail(email) {
						break
					}
					c.Println("Email is not valid.")
				}
	
				for {
					c.Print("Enter Password: ")
					password = c.ReadPassword()
				
					if utils.ValidatePassword(password) {
						c.Print("Confirm Password: ")
						confirmPassword := c.ReadPassword()
				
						if password == confirmPassword {
							break
						} else {
							c.Println()
							c.Println("Passwords do not match. Please try again.")
							c.Println()
						}
					} else {
						c.Println()
						c.Println("Password must be at least 8 characters and contain both letters and numbers.")
						c.Println()
					}
				}

				_, _, err := client.SignUp(username, email, password)
				if err != nil {
					utils.PrintError(err.Error())
					return
				}
				c.Println("Account created successfully. You are now signed in.")
				c.Println("Please check your email and confirm your account using the 'confirm' command.")
				loggedIn = true
				for _, command := range guestCommands {
					shell.DeleteCmd(command.Name)
				}
				addCommands(shell, userCommands)
			},
		},
		{
			Name: "forgotpassword",
			Desc: "Reset your account password",
			Func: func(c *ishell.Context) {
				var username, email, newPassword, confirmNewPassword, token string
		
				for {
					c.Print("Enter Username: ")
					username = c.ReadLine()
					if len(username) > 1 {
						break
					}
					c.Println("Username must be longer than 1 character.")
				}
		
				for {
					c.Print("Enter Email: ")
					email = c.ReadLine()
					if utils.ValidateEmail(email) {
						break
					}
					c.Println("Email is not valid.")
				}
		
				err := client.RequestPasswordReset(email)
				if err != nil {
					utils.PrintError("internal server error")
					return 
				}
				c.Println("A reset token has been sent to your email.")
		
				for {
					c.Print("Enter the Reset Token: ")
					token = c.ReadLine()
					if len(token) > 0 {
						break
					}
					c.Println("Please enter the token.")
				}
		
				err = client.VerifyPasswordToken(email, token)
				if err != nil {
					utils.PrintError("invalid or expired token. Please restart the password reset process.")
					return
				}
		
				for {
					c.Print("Enter New Password: ")
					newPassword = c.ReadPassword()
					c.Print("Confirm New Password: ")
					confirmNewPassword = c.ReadPassword()
					if confirmNewPassword == newPassword {
						break
					}
					c.Println("New passwords do not match. Please try again.")
				}
		
				err = client.ResetPassword(email, token, newPassword)
				if err != nil {
					utils.PrintError("internal server error")
					return 
				}
				c.Println("Password has been updated. Please log in.")
			},
		},
	}

	// Define the commands available to a signed in user
	userCommands = []Command{
		{
			Name: "updatemyacc",
			Desc: "Update your account information",
			Func: func(c *ishell.Context) {
				var currentPassword, newUsername, newEmail, newPassword string
		
				for {
					c.Print("Enter Current Password: ")
					currentPassword = c.ReadPassword()
		
					if len(currentPassword) > 0 {
						break
					}
					c.Println("Current password cannot be empty.")
				}
		
				for {
					c.Print("Do you want to update your username? (yes/no): ")
					response := strings.ToLower(c.ReadLine())
					if response == "yes" || response == "no" {
						if response == "yes" {
							for {
								c.Print("Enter New Username: ")
								newUsername = c.ReadLine()
			
								if len(newUsername) > 1 {
									break
								}
								c.Println("New username must be longer than 1 character.")
							}
						}
						break
					}
					c.Println("Invalid response. Please type 'yes' or 'no'.")
				}
			
				for {
					c.Print("Do you want to update your email? (yes/no): ")
					response := strings.ToLower(c.ReadLine())
					if response == "yes" || response == "no" {
						if response == "yes" {
							for {
								c.Print("Enter New Email: ")
								newEmail = c.ReadLine()
			
								if utils.ValidateEmail(newEmail) {
									break
								}
								c.Println("New email is not valid.")
							}
						}
						break
					}
					c.Println("Invalid response. Please type 'yes' or 'no'.")
				}
			
				for {
					c.Print("Do you want to update your password? (yes/no): ")
					response := strings.ToLower(c.ReadLine())
					if response == "yes" || response == "no" {
						if response == "yes" {
							for {
								c.Print("Enter New Password: ")
								newPassword := c.ReadPassword()
								
								if utils.ValidatePassword(newPassword) {
									c.Print("Confirm New Password: ")
									confirmPassword := c.ReadPassword()
									
									if newPassword == confirmPassword {
										break
									} else {
										c.Println()
										c.Println("Passwords do not match. Please try again.")
										c.Println()
									}
								} else {
									c.Println()
									c.Println("New password cannot be empty.")
									c.Println()
								}
							}
						}
						break
					}
					c.Println("Invalid response. Please type 'yes' or 'no'.")
				}
		
				err := client.UpdateUser(currentPassword, newUsername, newEmail, newPassword)
				if err != nil {
					if err.Error() == "expired refresh token" {
						utils.PrintError("Session expired, please sign in again by typing 'signin' in the terminal.")
						client.ClearKeyring()
						loggedIn = false
						for _, command := range userCommands {
							shell.DeleteCmd(command.Name)
						}
						addCommands(shell, guestCommands)
					} else {
						utils.PrintError(err.Error())
					}
					return
				}
				c.Println("Account updated successfully.")
			},
		},
		{
			Name: "signout",
			Desc: "Sign out from your account",
			Func: func(c *ishell.Context) {
				err := client.SignOut()
				if err != nil {
					utils.PrintError(err.Error())
					return
				}
				c.Println("You are now signed out.")
				loggedIn = false
				for _, command := range userCommands {
					shell.DeleteCmd(command.Name)
				}
				addCommands(shell, guestCommands)
			},
		},
		{
			Name: "deletemyacc",
			Desc: "Delete your account",
			Func: func(c *ishell.Context) {
				for {
					c.Print("Are you sure you want to delete your account? (yes/no): ")
					response := c.ReadLine()
					if strings.ToLower(response) == "no" {
						return
					} else if strings.ToLower(response) == "yes" {
						err := client.DeleteUser()
						if err != nil {
							if err.Error() == "expired refresh token" {
								utils.PrintError("Session expired, please sign in again by typing 'signin' in the terminal.")
								client.ClearKeyring()
								loggedIn = false
								for _, command := range userCommands {
									shell.DeleteCmd(command.Name)
								}
								addCommands(shell, guestCommands)
							} else {
								utils.PrintError(err.Error())
							}
							return
						}
						loggedIn = false
						c.Println("Account deleted successfully.")
						for _, command := range userCommands {
							shell.DeleteCmd(command.Name)
						}
						addCommands(shell, guestCommands)
					}
					c.Println("Invalid response. Please type 'yes' or 'no'.")
				}
			},
		},
		{
			Name: "confirm",
			Desc: "Confirm your account with the token sent to your email",
			Func: func(c *ishell.Context) {
				c.Print("Enter the confirmation token from your email: ")
				token := c.ReadLine()
				
				err := client.ConfirmEmail(token)
				if err != nil {
					utils.PrintError(err.Error())
					return
				}
				c.Println("Account activated successfully. You can now access all features.")
			},
		},
	}

	// Define common commands that are always available, regardless of login state
	commonCommands = []Command{
		{
			Name: "exit",
			Desc: "Exit the application",
			Func: func(c *ishell.Context) {
				fmt.Println("Goodbye!")
				os.Exit(0)
			},
		},
	}

	// The help command is created separately to avoid the cyclic dependency
	commonCommands = append(commonCommands, Command{
		Name: "help",
		Desc: "List available commands",
		Func: func(c *ishell.Context) {
			c.Println("Available commands:")
			if loggedIn {
				for _, command := range userCommands {
					c.Println("  |-- '" + command.Name + "' : " + command.Desc)
				}
			} else {
				for _, command := range guestCommands {
					c.Println("  |-- '" + command.Name + "' : " + command.Desc)
				}
			}
			for _, command := range commonCommands {
				c.Println("  |-- '" + command.Name + "' : " + command.Desc)
			}
			c.Println()
		},
	})
}

// addCommands is a helper function that adds the given commands to the shell.
//
// It accepts two arguments:
// - shell: The ishell shell where the commands will be added.
// - commands: A slice of Command structs to be added to the shell.
func addCommands(shell *ishell.Shell, commands []Command) {
	for _, command := range commands {
		shell.AddCmd(&ishell.Cmd{
			Name: command.Name,
			Help: "Command: " + command.Name,
			Func: command.Func,
		})
	}
}

// Execute is the main function that executes the shell.
// It welcomes the user, adds common and guest commands to the shell, and runs the shell.
func Execute() {
	shell.Println()
	figure.NewFigure("Virtuo", "basic", true).Print()
	shell.Println("Welcome to Virtuo -- the habit tracker CLI app. Type 'help' to see a list of commands.")

	addCommands(shell, commonCommands)
	addCommands(shell, guestCommands)

	shell.Run()
}