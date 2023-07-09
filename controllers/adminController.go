package controllers

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Nadeem1815/go-jwt/initializers"
	"github.com/Nadeem1815/go-jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func AdminSignup(c *gin.Context) {
	// Get the email and password req off req body
	var body struct {
		Email    string
		Password string
	}
	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}
	// Create admin
	admin := models.Admin{Email: body.Email, Password: string(hash)} //the hash is in byte type so converting it into string

	result := initializers.DB.Create(&admin)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Create Admin",
		})
		return
	}
	// Respond

	c.JSON(http.StatusOK, gin.H{
		"massage": "admin created",
	})

}

func AdminLogin(c *gin.Context) {
	// Get the password off req body
	var body struct {
		Email    string
		Password string
	}
	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}
	// look up req admin with the body
	var admin models.Admin
	initializers.DB.First(&admin, "email=?", body.Email)
	if admin.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return

	}

	// Compare sent in password with hashed password in the db

	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": admin.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECERET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	// sent it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"massage": "cookie is created",
	})
}

func AdminValidate(c *gin.Context) {
	// admin, _ := c.Get("admin")

	c.JSON(http.StatusOK, gin.H{
		"massage": "admin validated",
	})
}

func AdminLogut(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache,no-store,must-revalidate")
	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"massage": "logout successfully",
	})
}

func FindUsers(c *gin.Context) {
	var user []models.User

	name := c.Query("search")
	fmt.Println(name)
	if name != "" {

		record := initializers.DB.Raw("select email from users where email like ?", "%"+name).Scan(&user)
		fmt.Println(user)
		if record.Error != nil {
			c.JSON(500, gin.H{
				"err": record.Error.Error(),
			})

			return
		}
		c.JSON(200, gin.H{

			"messege": user,
		})

	} else {

		result := initializers.DB.Find(&user)
		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "No users Found",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"massage": user,
		})
	}
}
func Find(c *gin.Context) {
	// var body struct {
	// 	User_id int `json:"userid"`
	// }
	// if err := c.Bind(&body); err != nil {
	// 	c.JSON(http.StatusBadRequest, err.Error())
	// 	return
	// }
	paramsID := c.Param("id")
	id, err := strconv.Atoi(paramsID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot parse id",
		})
		return
	}
	var user models.User
	initializers.DB.First(&user, "id=?", id)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "no user found",
		})
		return

	} else {
		c.JSON(http.StatusOK, gin.H{
			"massage": user,
		})

	}
}

// func FindUsers(c *gin.Context) {
// 	// Geting  email

// 	initializers.DB.First(&user, "email=?", body.Email)
// 	if user.ID == 0 {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"err": "No user found",
// 		})
// 		return

// 	} else {
// 		c.JSON(http.StatusOK, gin.H{
// 			"massage": user,
// 		})
// 	}
// }

func DeleteUsers(c *gin.Context) {
	var body struct {
		Email string
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}
	var user models.User
	initializers.DB.Delete(&user, "email=?", body.Email)
	c.JSON(http.StatusOK, gin.H{
		"massage": "user deleted",
	})
}

func CreateUsers(c *gin.Context) {
	// Get the email/pass off req body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Create the user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return

	}
	// Respond
	c.JSON(http.StatusOK, gin.H{
		"massage": "user created",
	})
}

func UpdateUser(c *gin.Context) {
	var body struct {
		Email        string
		New_password string
	}
	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "error to bind body",
		})
		return

	}
	// hash the pawssrod

	hash, err := bcrypt.GenerateFromPassword([]byte(body.New_password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to hash password",
		})
		return
	}
	user := models.User{Password: string(hash)}

	result := initializers.DB.Model(&user).Where("email = ?", body.Email).Update("password", string(hash))
	fmt.Println(result)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to update password",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"massage": "successfully change password",
	})
}
