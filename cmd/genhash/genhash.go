package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	var pass string
	// если передан аргумент — используем его
	if len(os.Args) > 1 {
		pass = os.Args[1]
	} else {
		// если stdin не терминал — читаем из пайпа/редиректа
		fi, _ := os.Stdin.Stat()
		if fi.Mode()&os.ModeCharDevice == 0 {
			r := bufio.NewReader(os.Stdin)
			b, _ := r.ReadString('\n')
			pass = strings.TrimSpace(b)
		} else {
			// интерактивно: скрытый ввод
			fmt.Print("Password: ")
			b, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read password: %v\n", err)
				os.Exit(2)
			}
			pass = string(b)
		}
	}

	if pass == "" {
		fmt.Fprintln(os.Stderr, "empty password")
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt error: %v\n", err)
		os.Exit(3)
	}
	fmt.Println(string(hash))
}
