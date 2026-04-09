# SFTP сервер (Go)

Краткое описание
- Небольшой SFTP сервер на Go, использующий пароли.
- Пользователи хранятся в файле `users.json` рядом с исполняемым файлом. Формат: JSON объект "username": "bcrypt_hash".

Требования
- Go 1.20+
- Зависимости: github.com/pkg/sftp, golang.org/x/crypto/ssh, golang.org/x/crypto/bcrypt

Запуск
1. Инициализируйте модуль (если ещё не):
   go mod init sftp
   go get github.com/pkg/sftp
   go get golang.org/x/crypto/ssh
   go get golang.org/x/crypto/bcrypt
   go mod tidy

2. Запустите сервер:
   go run main.go

По умолчанию при первом запуске будет создан `users.json` с пользователем:
- Пользователь: `copyuser`
- Пароль: `copy123` (в файле хранится bcrypt‑хэш)

Расположение
- `host_key.pem` — приватный ключ хоста (создаётся при первом запуске).
- `users.json` — JSON с bcrypt-хэшами паролей, находится рядом с exe.

Формат users.json
Пример:
{
  "copyuser": "$2a$10$...bcrypt hash..."
}

Как добавить/изменить пользователя
1. Рекомендуется сгенерировать bcrypt‑хэш и вручную внести в `users.json`.
2. Примеры генерации хэша:

 - Утилита в `cmd/genhash` (отдельная команда):
   - Интерактивно: `go run ./cmd/genhash` (скрыт ввод пароля).
   - С аргументом: `go run ./cmd/genhash mypassword`
   - Через пайп: `echo -n "mypassword" | go run ./cmd/genhash`
   - Собрать бинарник: `go build -o genhash ./cmd/genhash` и затем `./genhash` (Windows: `genhash.exe`).

- Альтернатива: небольшой скрипт:
  ```go
  package main

  import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
  )

  func main() {
    pass := "yourpassword"
    hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
    if err != nil {
      panic(err)
    }
    fmt.Println(string(hash))
  }
  ```

Безопасность
- Храните `users.json` и `host_key.pem` в безопасном месте; файлы создаются с правами 0600.
- Для продакшена смените дефолтный пароль и добавьте пользователей с уникальными паролями.
- При необходимости используйте отдельный механизм управления пользователями (ACL, chroot и т.д.).

Подсказки
- Если запускаете на другом компьютере — откройте порт 2222 в брандмауэре (Windows PowerShell пример в комментариях main.go).
- Для управления пользователями можно добавить простую утилиту в проект, которая будет использовать ту же функцию bcrypt.GenerateFromPassword и обновлять users.json.
