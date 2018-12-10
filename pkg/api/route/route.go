package route

import (
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Http   *echo.Echo
	Logger *logrus.Entry
}
