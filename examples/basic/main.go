package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	platformauth "github.com/microservice-tech/platform-auth-go"
	"github.com/microservice-tech/platform-auth-go/middleware"
)

func main() {
	// Initialize JWT validator
	validator, err := platformauth.NewValidator(platformauth.Config{
		PublicKeyPath:    "/keys/gateway-public.pem",
		ExpectedIssuer:   "platform-gateway",
		ExpectedAudience: "internal-services",
	})
	if err != nil {
		log.Fatalf("Failed to initialize validator: %v", err)
	}

	// Create JWT middleware
	jwtMiddleware := middleware.NewJWT(validator)

	// Setup router
	router := mux.NewRouter()

	// Health endpoint (no auth)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}).Methods("GET")

	// Protected API routes
	api := router.PathPrefix("/api").Subrouter()
	api.Use(jwtMiddleware.Handler)
	api.Use(middleware.RequireModule("example_module"))

	// Public endpoint (just needs valid JWT)
	api.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.GetClaims(r.Context())
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Hello",
			"user_id":   claims.UserID,
			"tenant_id": claims.TenantID,
		})
	}).Methods("GET")

	// Admin endpoint (requires admin role)
	api.Handle("/admin",
		middleware.RequireRole("admin")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"message": "Admin access granted"})
			}),
		),
	).Methods("GET")

	// Management endpoint (requires specific permission)
	api.Handle("/manage",
		middleware.RequirePermission("can_manage_users")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"message": "Management access granted"})
			}),
		),
	).Methods("GET")

	// Feature endpoint (requires specific feature)
	api.Handle("/export",
		middleware.RequireFeature("api_access")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"message": "Export feature enabled"})
			}),
		),
	).Methods("GET")

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
