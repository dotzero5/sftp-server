// Если будете подключаться с другого компьютера, не забудьте открыть порт 2222 в брандмауэре Windows (на компьютере с сервером):
// powershell
// New-NetFirewallRule -DisplayName "SFTP Server" -Direction Inbound -Protocol TCP -LocalPort 2222 -Action Allow
// Инициализируйте Go модуль
// go mod init sftp
// Установите зависимости
// go get github.com/pkg/sftp
// go get golang.org/x/crypto/ssh
// Обновите зависимости
// go mod tidy
// Запустите сервер
// go run main.go
// или компиляция
// go build
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func main() {
	// Загружаем или создаём приватный ключ хоста (persisted)
	privateKey, created, err := loadOrCreatePrivateKey("host_key.pem")
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Println("🔐 Создан и сохранён хост-ключ: host_key.pem")
	} else {
		log.Println("🔐 Загружен хост-ключ: host_key.pem")
	}

	// Определяем путь к users.json (рядом с исполняемым файлом)
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exeDir := filepath.Dir(exePath)
	// If the executable is in the system temp dir (go run), use the current working dir
	if temp := os.TempDir(); temp != "" && filepath.HasPrefix(exeDir, temp) {
		if wd, err := os.Getwd(); err == nil {
			exeDir = wd
		}
	}
	usersPath := filepath.Join(exeDir, "users.json")

	// Загружаем или создаём файл пользователей (JSON + bcrypt)
	users, createdUsers, err := loadOrCreateUsers(usersPath)
	if err != nil {
		log.Fatal(err)
	}
	if createdUsers {
		log.Printf("🗄️ Создан users.json с дефолтным пользователем (copyuser)")
	} else {
		log.Printf("🗄️ Загружен users.json (%s)", usersPath)
	}

	// Конвертируем в формат SSH
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Настройки сервера: проверяем через bcrypt-хэши из users
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			username := conn.User()
			hash, ok := users[username]
			if !ok {
				log.Printf("❌ Неизвестный пользователь %s", username)
				return nil, fmt.Errorf("password rejected for user %s", username)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
				log.Printf("❌ Неудачная попытка входа для %s", username)
				return nil, fmt.Errorf("password rejected for user %s", username)
			}
			log.Printf("✅ Пользователь %s подключился", username)
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)

	// Запуск сервера
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("🚀 SFTP сервер запущен на порту 2222")
	log.Println("👤 Пользователь: copyuser")
	log.Println("🔑 Пароль: copy123")
	log.Println("📁 Доступ: весь диск C:")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleConn(conn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Ошибка SSH рукопожатия: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("🔌 Клиент подключен: %s", sshConn.RemoteAddr())

	// Обрабатываем глобальные запросы
	go ssh.DiscardRequests(reqs)

	// Обрабатываем каналы
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Ошибка принятия канала: %v", err)
			continue
		}

		go handleSession(channel, requests)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "subsystem":
			// Проверяем, запрашивают ли SFTP подсистему
			if len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
				if req.WantReply {
					req.Reply(true, nil)
				}
				// Создаем и запускаем SFTP сервер
				server, err := sftp.NewServer(channel)
				if err != nil {
					log.Printf("Ошибка создания SFTP сервера: %v", err)
					return
				}
				if err := server.Serve(); err != nil {
					log.Printf("SFTP сервер ошибка: %v", err)
				}
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}

		case "shell", "exec":
			// Отказываемся от запуска shell/команд
			if req.WantReply {
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// loadOrCreatePrivateKey пытается загрузить PEM RSA ключ из path.
// Если файла нет — генерирует новый 2048-bit RSA и сохраняет в path (0600).
func loadOrCreatePrivateKey(path string) (*rsa.PrivateKey, bool, error) {
	// существует файл — загрузить
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, false, fmt.Errorf("invalid PEM in %s", path)
		}
		// Попытка PKCS1
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, false, nil
		}
		// Попытка PKCS8
		if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if rsaKey, ok := parsed.(*rsa.PrivateKey); ok {
				return rsaKey, false, nil
			}
			return nil, false, fmt.Errorf("PEM does not contain RSA key")
		}
		return nil, false, fmt.Errorf("failed to parse private key in %s", path)
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}

	// Файл не найден — генерируем и сохраняем
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// loadOrCreateUsers загружает users.json как map[username]bcryptHash.
// Если файла нет — создаёт его с дефолтным пользователем copyuser:copy123.
func loadOrCreateUsers(path string) (map[string]string, bool, error) {
	// существует файл — загрузить
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, err
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, false, err
		}
		return m, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}

	// Файл не найден — создаём с дефолтом
	defaultPass := "copy123"
	hash, err := bcrypt.GenerateFromPassword([]byte(defaultPass), bcrypt.DefaultCost)
	if err != nil {
		return nil, false, err
	}
	m := map[string]string{
		"copyuser": string(hash),
	}
	if err := saveUsers(path, m); err != nil {
		return nil, false, err
	}
	return m, true, nil
}

// saveUsers сохраняет map в JSON файл с правами 0600.
func saveUsers(path string, m map[string]string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Сохраняем в том же каталоге (пермишены 0600)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}
