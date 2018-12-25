package models

import "golang.org/x/crypto/bcrypt"

type CryptConfig struct {
	Cost int
}

type BcryptEncryptor struct {
	*CryptConfig
}

func NewBcryptEncryptor(config *CryptConfig) *BcryptEncryptor {
	if config == nil {
		config = &CryptConfig{}
	}

	if config.Cost == 0 {
		config.Cost = bcrypt.DefaultCost
	}

	return &BcryptEncryptor{config}
}

func (be *BcryptEncryptor) Digest(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), be.Cost)
	return string(hashedPassword), err
}

func (be *BcryptEncryptor) Compare(hashedPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
