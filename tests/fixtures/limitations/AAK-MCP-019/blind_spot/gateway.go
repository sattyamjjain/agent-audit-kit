package gateway

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, store AdapterStore) {
	adapters := r.Group("/api/v1/adapters")
	adapters.POST("/tools", func(c *gin.Context) {
		listMCPTools(c, store)
	})
}

// The same order, with the adapter's name taken from the JSON body: the
// check follows only path, query and form parameters.
func listMCPTools(c *gin.Context, store AdapterStore) {
	var body struct {
		Adapter string `json:"adapter"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	adapter, err := store.Get(c.Request.Context(), body.Adapter)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "adapter not found"})
		return
	}

	if adapter.AuthRequired {
		if err := checkClientToken(c, adapter.Token); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
	}

	forwardMCP(c, adapter, "tools/list")
}
