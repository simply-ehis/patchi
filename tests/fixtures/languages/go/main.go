package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var users = []User{}
var nextID = 1

func main() {
	r := gin.Default()

	r.GET("/users", getUsers)
	r.GET("/users/:id", getUser)
	r.POST("/users", createUser)
	r.PUT("/users/:id", updateUser)
	r.DELETE("/users/:id", deleteUser)
	r.GET("/search", searchUsers)

	r.Run()
}

func getUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": users, "count": len(users)})
}

func getUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	for _, u := range users {
		if u.ID == id {
			c.JSON(http.StatusOK, gin.H{"item": u})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
}

func createUser(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u.ID = nextID
	nextID++
	users = append(users, u)
	c.JSON(http.StatusCreated, gin.H{"item": u})
}

func updateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	for i, u := range users {
		if u.ID == id {
			var updated User
			if err := c.ShouldBindJSON(&updated); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			updated.ID = id
			users[i] = updated
			c.JSON(http.StatusOK, gin.H{"item": updated})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
}

func deleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	for i, u := range users {
		if u.ID == id {
			users = append(users[:i], users[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
}

func searchUsers(c *gin.Context) {
	query := c.Query("q")
	var results []User
	for _, u := range users {
		if contains(u.Name, query) {
			results = append(results, u)
		}
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

func unusedFunction() string {
	return "dead code"
}
