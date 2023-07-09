package main

import (
	"github.com/Nadeem1815/go-jwt/controllers"
	"github.com/Nadeem1815/go-jwt/initializers"
	"github.com/Nadeem1815/go-jwt/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnVariables()
	initializers.ConnectToDb()
	initializers.SycnDatabase()
}

func main() {
	r := gin.Default()
	// user
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.UserAuth, controllers.Validate)
	r.POST("/userlogut", controllers.UserLogut)

	// admin
	r.POST("/adminsignup", controllers.AdminSignup)
	r.POST("/adminlogin", controllers.AdminLogin)
	r.GET("/adminvalidate", middleware.AdminAuth, controllers.AdminValidate)
	r.POST("/adminlogut", controllers.AdminLogut)

	r.GET("/findusers", middleware.AdminAuth, controllers.FindUsers)
	// r.POST("/findusers", middleware.AdminAuth, controllers.FindUsers)
	r.DELETE("/deleteusers", middleware.AdminAuth, controllers.DeleteUsers)
	r.POST("/adduser", middleware.AdminAuth, controllers.CreateUsers)
	r.PATCH("/updateuser", middleware.AdminAuth, controllers.UpdateUser)
	r.GET("/find/:id", middleware.AdminAuth, controllers.Find)
	r.Run()
}
