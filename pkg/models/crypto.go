package models

import "golang.org/x/crypto/bcrypt"

// CryptConfig is configuration parameters for the bcrypt encryptor
type CryptConfig struct {
	Cost int
}

// BcryptEncryptor is the bcrypt encryptor service
type BcryptEncryptor struct {
	*CryptConfig
}

// NewBcryptEncryptor return new bcrypt encryptor service
func NewBcryptEncryptor(config *CryptConfig) *BcryptEncryptor {
	if config == nil {
		config = &CryptConfig{}
	}

	if config.Cost == 0 {
		config.Cost = bcrypt.DefaultCost
	}

	return &BcryptEncryptor{config}
}

// Digest is creates encrypted password.
func (be *BcryptEncryptor) Digest(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), be.Cost)
	return string(hashedPassword), err
}

// Compare is compared original password and encrypted string.
func (be *BcryptEncryptor) Compare(hashedPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
