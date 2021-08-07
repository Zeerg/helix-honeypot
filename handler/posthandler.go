package handler

import (
	"github.com/labstack/echo/v4"

)

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
  }

//Pods Handler
func PostHandler(c echo.Context) error {
	u := &User{
		Name:  "Nice",
		Email: "42069",
	  }
	return c.JSON(201, u)
}
