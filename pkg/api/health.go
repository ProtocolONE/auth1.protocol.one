package api

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"gopkg.in/tomb.v2"
	"net/http"
)

func InitHealth(cfg *Server) error {
	cfg.Echo.GET("/health", health)
	cfg.Echo.GET("/test", test)

	return nil
}

func health(ctx echo.Context) error {
	return ctx.HTML(http.StatusNoContent, ``)
}

func test(ctx echo.Context) error {
	t, _ := tomb.WithContext(ctx.Request().Context())
	hash1 := ""
	hash2 := ""
	t.Go(func() error {
		var err error
		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: 20})
		hash1, err = be.Digest("additional tracked goroutines")
		if err != nil {
			return err
		}
		fmt.Println("Hash1 is digest")
		return nil
	})
	t.Go(func() error {
		var err error
		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: 4})
		hash2, err = be.Digest("a")
		if err != nil {
			return err
		}
		fmt.Println("Hash2 is digest")
		return nil
	})
	fmt.Println("Go to waiting")
	if err := t.Wait(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("Waiting completed")
	fmt.Println(hash1)
	fmt.Println(hash2)
	return nil
}
