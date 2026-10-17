package gateway

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, store AdapterStore) {
	adapters := r.Group("/api/v1/adapters")
	adapters.GET("/:name/tools", func(c *gin.Context) {
		listMCPTools(c, store)
	})
}

// listMCPTools answers 404 for an unknown adapter before it checks the
// caller's token, so a caller with no token learns which adapters exist.
func listMCPTools(c *gin.Context, store AdapterStore) {
	name := c.Param("name")

	adapter, err := store.Get(c.Request.Context(), name)
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
