## Практическое занятие №9 Реализация регистрации и входа пользователей. Хэширование паролей с bcrypt
## Седова М.А., ЭФМО-01-25

## Окружение проекта
Операционная система:
- СУБД: PostgreSQL 14+
- Go: Версия 1.21+
- Go модули: Используются (go.mod)
- Git: Для контроля версий
- Postman: Для тестирования API

## Цели работы 
-	Научиться безопасно хранить пароли (bcrypt), валидировать вход и обрабатывать ошибки.
-	Реализовать эндпоинты POST /auth/register и POST /auth/login.
-	Закрепить работу с БД (PostgreSQL + GORM или database/sql) и валидацией ввода.

## Дерево
<img width="381" height="487" alt="image" src="https://github.com/user-attachments/assets/d41d3b14-a3a7-4425-9afd-82a72fa09142" />

## Скриншоты:
- Успешная регистрация (201 Created)
- <img width="1280" height="567" alt="image" src="https://github.com/user-attachments/assets/e811bce6-670f-4c2a-97d8-3631036dbdc6" />
- Повторная попытка (409 Conflict),
- <img width="1280" height="432" alt="image" src="https://github.com/user-attachments/assets/c265d22f-a656-46e8-8ead-8dd43b02ebb3" />
-	Вход с верными данными (200 OK),
-	<img width="1280" height="554" alt="image" src="https://github.com/user-attachments/assets/6b696828-350a-4d2a-83be-fc41431c2dc4" />
-	Вход с неверными данными (401 Unauthorized)
-	<img width="1280" height="493" alt="image" src="https://github.com/user-attachments/assets/a0fbbd8d-3a25-4cc1-824a-00b610a16cde" />
- Валидация
- <img width="1280" height="478" alt="image" src="https://github.com/user-attachments/assets/a24d7f64-3fcd-4ab9-9022-66a2918ed002" />

## Фрагменты кода
- обработчик Register (/root/pz9-auth/internal/http/handlers/auth.go)
```
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
    var in registerReq
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        writeErr(w, http.StatusBadRequest, "invalid_json")
        return
    }
    
    in.Email = strings.TrimSpace(strings.ToLower(in.Email))
    if in.Email == "" || len(in.Password) < 8 {
        writeErr(w, http.StatusBadRequest, "email_required_and_password_min_8")
        return
    }

    // bcrypt hash - МЕСТО ВЫЗОВА bcrypt.GenerateFromPassword
    hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), h.BcryptCost)
    if err != nil {
        writeErr(w, http.StatusInternalServerError, "hash_failed")
        return
    }

    u := core.User{Email: in.Email, PasswordHash: string(hash)}
    if err := h.Users.Create(r.Context(), &u); err != nil {
        if err == repo.ErrEmailTaken {
            writeErr(w, http.StatusConflict, "email_taken")
            return
        }
        writeErr(w, http.StatusInternalServerError, "db_error")
        return
    }

    writeJSON(w, http.StatusCreated, authResp{
        Status: "ok",
        User:   map[string]any{"id": u.ID, "email": u.Email},
    })
}
```

- Обработчик Login (/root/pz9-auth/internal/http/handlers/auth.go)
```
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var in loginReq
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        writeErr(w, http.StatusBadRequest, "invalid_json")
        return
    }
    
    in.Email = strings.TrimSpace(strings.ToLower(in.Email))
    if in.Email == "" || in.Password == "" {
        writeErr(w, http.StatusBadRequest, "email_and_password_required")
        return
    }

    u, err := h.Users.ByEmail(context.Background(), in.Email)
    if err != nil {
        writeErr(w, http.StatusUnauthorized, "invalid_credentials")
        return
    }

    // МЕСТО ВЫЗОВА bcrypt.CompareHashAndPassword
    if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
        writeErr(w, http.StatusUnauthorized, "invalid_credentials")
        return
    }

    writeJSON(w, http.StatusOK, authResp{
        Status: "ok",
        User:   map[string]any{"id": u.ID, "email": u.Email},
    })
}
```

- Структура запросов
```
type registerReq struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type loginReq struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type authResp struct {
    Status string      `json:"status"`
    User   interface{} `json:"user,omitempty"`
}
```

4.	SQL/миграции (или подтверждение AutoMigrate)
- Подтверждение использования AutoMigrate ( /root/pz9-auth/internal/repo/user_repo.go)
```
func (r *UserRepo) AutoMigrate() error {
    return r.db.AutoMigrate(&core.User{})
}
```

- Вызов AutoMigrate в main.go:
```
users := repo.NewUserRepo(db)
if err := users.AutoMigrate(); err != nil {
    log.Fatal("migrate:", err)
}
```

- SQL схема создаваемая AutoMigrate
```
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_users_email ON users(email);
```

- Ручное создание БД (выполнено на сервере)
```
CREATE DATABASE pz9_auth;
CREATE USER auth_user WITH PASSWORD 'auth_password_123';
GRANT ALL PRIVILEGES ON DATABASE pz9_auth TO auth_user;
GRANT ALL ON SCHEMA public TO auth_user;
GRANT CREATE ON SCHEMA public TO auth_user;
```

5.	Команды запуска, переменные окружения 
- Переменные окружения (/root/pz9-auth/internal/platform/config/config.go)
```
type Config struct {
    DB_DSN      string
    BcryptCost  int
    Addr        string
}

func Load() Config {
    cost := 12 
    if v := os.Getenv("BCRYPT_COST"); v != "" {
        if parsed, err := strconv.Atoi(v); err == nil {
            cost = parsed
        }
    }
    
    addr := os.Getenv("APP_ADDR")
    if addr == "" {
        addr = ":8084
    }

    return Config{
        DB_DSN:     os.Getenv("DB_DSN"),
        BcryptCost: cost,
        Addr:       addr,
    }
}
```

- Команды запуска
```
# Сборка
cd ~/pz9-auth
go build -o app ./cmd/api
```

```
# Запуск
DB_DSN="host=localhost user=auth_user password=auth_password_123 dbname=pz9_auth port=5432 sslmode=disable" \
./app
```

- URL http://37.230.117.32:8084/auth/register

6.	Краткие выводы: почему нельзя хранить пароли в открытом виде; почему bcrypt.
Хранить пароли в открытом виде нельзя, потому что при утечке базы данных или компрометации сервера злоумышленники смогут получить все пароли полностью, что ставит под угрозу безопасность пользователей и других связанных систем, в т.ч. из-за повторного использования паролей. Вместо этого пароли хранятся в виде хэшей — односторонних функций, которые превращают пароль в набор данных, обратное вычисление которого невозможно. Для усиления безопасности к паролю добавляют соль — случайные данные, которые делают одинаковые пароли различными по хэшу. 

Контрольные вопросы
1.	В чём разница между хранением пароля и хранением его хэша? Зачем соль? Почему bcrypt, а не SHA-256? 
(п. 6) + bcrypt выбирается вместо простого SHA-256, поскольку bcrypt включает встроенную соль и является "медленной" хэш-функцией, что защищает от ускоренных атак перебора паролей. SHA-256 слишком быстр и не содержит встроенной соли, что делает его уязвимым к атакам перебора и радужным таблицам. 
2.	Что произойдёт при снижении/повышении cost у bcrypt? Как подобрать значение?
Параметр cost в bcrypt регулирует количество вычислительных итераций: повышение cost увеличивает время хэширования, что повышает защиту, но требует больше ресурсов. Его значение подбирают исходя из баланса безопасности и производительности, чтобы время проверки пароля было комфортным для пользователя, но достаточно долгим для затруднения атак. 
3.	Какие статусы и ответы должны возвращать POST /auth/register и POST /auth/login в типичных сценариях?
По API аутентификации: 
- POST /auth/register должен возвращать статус успеха при удачной регистрации, а при ошибках (например, пользователь существует) — соответствующий статус с безопасным сообщением. 
- POST /auth/login возвращает статус успешной аутентификации или ошибки при неверных данных. Подробные ошибки раскрывать не стоит, чтобы не помогать злоумышленникам.
4.	Какие риски несут подробные сообщения об ошибках при логине?
Подробные сообщения об ошибках при логине несут риск раскрытия информации о наличии пользователя или причине отказа, что может облегчить атаки перебором или разведку уязвимых точек.
5.	Почему в этом ПЗ не выдаём токен, и что изменится в ПЗ10 (JWT)? 
В текущем задании токен не выдается, возможно, для упрощения или из соображений безопасности. В следующем задании (ПЗ10) планируется ввод JWT (JSON Web Token), что позволит безопасно управлять сессиями и авторизацией без постоянной проверки пароля на сервере.
