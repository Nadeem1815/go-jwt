package initializers

import (
	// "fmt"

	"github.com/Nadeem1815/go-jwt/models"
)

func SycnDatabase() {
	// Migrate the schema
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.Admin{})

}
