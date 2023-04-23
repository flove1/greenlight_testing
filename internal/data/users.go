package data

import (
	"context" // New import
	"crypto/sha256"
	"database/sql" // New import
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"greenlight.bcc/internal/validator"
)

var (
	ErrDuplicateEmail = errors.New("duplicate email")
)

var AnonymousUser = &User{}

type User struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  password  `json:"-"`
	Activated bool      `json:"activated"`
	Version   int       `json:"-"`
}

func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
}

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be a valid email address")
}

func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(len(password) >= 8, "password", "must be at least 8 bytes long")
	v.Check(len(password) <= 72, "password", "must not be more than 72 bytes long")
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(user.Name != "", "name", "must be provided")
	v.Check(len(user.Name) <= 500, "name", "must not be more than 500 bytes long")

	ValidateEmail(v, user.Email)

	if user.Password.plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.plaintext)
	}

	if user.Password.hash == nil {
		panic("missing password hash for user")
	}

}

type password struct {
	plaintext *string
	hash      []byte
}

func (p *password) Set(plaintextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), 12)
	if err != nil {
		return err
	}
	p.plaintext = &plaintextPassword
	p.hash = hash
	return nil
}

func (p *password) Matches(plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.hash, []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

type UserModel struct {
	DB *sql.DB
}

func (m UserModel) Insert(user *User) error {
	query := `
	INSERT INTO users (name, email, password_hash, activated)
	VALUES ($1, $2, $3, $4)
	RETURNING id, created_at, version`
	args := []any{user.Name, user.Email, user.Password.hash, user.Activated}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.CreatedAt, &user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		default:
			return err
		}
	}

	return nil
}

func (m UserModel) GetByEmail(email string) (*User, error) {
	query := `
	SELECT id, created_at, name, email, password_hash, activated, version
	FROM users
	WHERE email = $1`
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := m.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Name,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}

func (m UserModel) Update(user *User) error {
	query := `
	UPDATE users
	SET name = $1, email = $2, password_hash = $3, activated = $4, version = version + 1
	WHERE id = $5 AND version = $6
	RETURNING version`
	args := []any{
		user.Name,
		user.Email,
		user.Password.hash,
		user.Activated,
		user.ID,
		user.Version,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		case errors.Is(err, sql.ErrNoRows):
			return ErrEditConflict
		default:
			return err
		}
	}
	return nil
}

func (m UserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {
	tokenHash := sha256.Sum256([]byte(tokenPlaintext))

	query := `
	SELECT users.id, users.created_at, users.name, users.email, users.password_hash, users.activated, users.version
	FROM users
	INNER JOIN tokens
	ON users.id = tokens.user_id
	WHERE tokens.hash = $1
	AND tokens.scope = $2
	AND tokens.expiry > $3`

	args := []any{tokenHash[:], tokenScope, time.Now()}
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Name,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

type MockUserModel struct {
	DB *sql.DB
}

func (m MockUserModel) Insert(user *User) error {
	if user.Email == "exists@test.com" {
		return ErrDuplicateEmail
	}
	if user.Email == "errorInsert@test.com" {
		return errors.New("test")
	}
	if user.Email == "errorPermissions@test.com" {
		user.ID = 2
	} else if user.Email == "errorTokens@test.com" {
		user.ID = 3
	} else {
		user.ID = 1
	}
	return nil
}

func (m MockUserModel) GetByEmail(email string) (*User, error) {
	if email == "error@test.com" {
		return nil, errors.New("test")
	}
	if email == "notFound@test.com" {
		return nil, ErrRecordNotFound
	}

	user := &User{
		ID:    1,
		Email: email,
	}
	user.Password.Set("pa$$word")

	if email == "notMatch@test.com" {
		user.Password.Set("passwordNotMatch")
	}
	if email == "errorToken@test.com" {
		user.ID = 2
	}

	return user, nil
}

func (m MockUserModel) Update(user *User) error {
	if user.Email == "updateConflict@test.com" {
		return ErrEditConflict
	} else if user.Email == "updateError@test.com" {
		return errors.New("test")
	}

	return nil
}

func (m MockUserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {
	switch tokenPlaintext {
	case strings.Repeat("b", 26):
		return nil, ErrRecordNotFound
	case strings.Repeat("c", 26):
		return nil, errors.New("test")
	case strings.Repeat("d", 26):
		user := User{
			ID:        1,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "updateConflict@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	case strings.Repeat("e", 26):
		user := User{
			ID:        1,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "updateError@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	case strings.Repeat("f", 26):
		user := User{
			ID:        -1,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "test@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	case strings.Repeat("g", 26):
		user := User{
			ID:        1,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "test@test.com",
			Activated: false,
		}
		user.Password.Set("password")
		return &user, nil
	case strings.Repeat("h", 26):
		user := User{
			ID:        2,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "test@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	case strings.Repeat("k", 26):
		user := User{
			ID:        3,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "test@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	default:
		user := User{
			ID:        1,
			CreatedAt: time.Now(),
			Name:      "test",
			Email:     "test@test.com",
			Activated: true,
		}
		user.Password.Set("password")
		return &user, nil
	}
}
