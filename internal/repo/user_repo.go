package repo

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
	"example.com/pz9-auth/internal/core"
)

var ErrUserNotFound = errors.New("user not found")
var ErrEmailTaken = errors.New("email already in use")

type UserRepo struct{ db *gorm.DB }

func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) AutoMigrate() error {
	return r.db.AutoMigrate(&core.User{})
}

func (r *UserRepo) Create(ctx context.Context, u *core.User) error {
    if err := r.db.WithContext(ctx).Create(u).Error; err != nil {
        // Проверяем ошибку дублирования email
        if strings.Contains(err.Error(), "duplicate key value") || 
           strings.Contains(err.Error(), "23505") ||
           errors.Is(err, gorm.ErrDuplicatedKey) {
            return ErrEmailTaken
        }
        return err
    }
    return nil
}

func (r *UserRepo) ByEmail(ctx context.Context, email string) (core.User, error) {
	var u core.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return core.User{}, ErrUserNotFound
	}
	return u, err
}
