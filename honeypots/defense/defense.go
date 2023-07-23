package defense

import (
	"github.com/labstack/echo/v4"
	"helix-honeypot/model"
	"helix-honeypot/logger"

	"net/http"
	"math/rand"
	crand "crypto/rand"
	"strconv"
)

// Literally streams cruff to the response
func ActiveDefenseHandler(c echo.Context) error {
	prng := crand.Reader
	return c.Stream(http.StatusCreated, "application/json", prng)
}

// RedirectLoopHandler serves a redirect loop that follows a sequence of URLs from "a" to "z"
func RedirectLoopHandler(c echo.Context) error {
	// Get the current redirect index from the query parameter "index"
	index := c.QueryParam("index")
	if index == "" {
		index = "0"
	}

	// Convert the index to an integer
	redirectIndex := 0
	// Handle any conversion errors
	if i, err := strconv.Atoi(index); err == nil && i >= 0 {
		redirectIndex = i
	}

	// Calculate the next character in the sequence
	nextIndex := (redirectIndex + 1) % 26
	nextChar := string('a' + nextIndex)

	// Set the next redirect URL
	nextURL := "/" + nextChar

	// Set response headers for the forever redirect
	c.Response().Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Response().Header().Set("Pragma", "no-cache")
	c.Response().Header().Set("Expires", "0")
	c.Response().Header().Set("Location", nextURL)

	// Send the forever redirect response
	return c.Redirect(http.StatusMovedPermanently, nextURL)
}

// RandomHandler randomly chooses between ActiveDefenseHandler and RedirectLoopHandler
func RandomHandler(c echo.Context) error {
	handlers := []func(echo.Context) error{
		ActiveDefenseHandler,
		func(c echo.Context) error {
			return RedirectLoopHandler(c)
		},
	}

	// Randomly select a handler
	randomIndex := rand.Intn(len(handlers))
	selectedHandler := handlers[randomIndex]

	// Execute the selected handler
	return selectedHandler(c)
}

func StartDefenseHoneypot(cfg *model.Config) {
	e := NewRouter()

	// Initialize logger
	customLogger, err := logger.NewCustomLogger(cfg)
	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	// Set the logger middleware
	e.Use(customLogger.Middleware)
	// Routes for Active Defense Mode
	e.GET("/*", RandomHandler)
	e.POST("/*", RandomHandler)

	e.Logger.Fatal(e.Start(cfg.DEF.Host + ":" + cfg.DEF.Port))
}