package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	port   = 3000
	dbPath = "./database.sqlite"
)

type User struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Registered string `json:"registered"`
}

type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// Структура для запроса на смену пароля
type ChangePasswordRequest struct {
	Email       string `json:"email"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type Product struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	ImageURL    string  `json:"image_url"`
	Platform    string  `json:"platform"`     // Платформа
	Genre       string  `json:"genre"`        // Жанр
	Developer   string  `json:"developer"`    // Разработчик
	Publisher   string  `json:"publisher"`    // Издатель
	Rating      float64 `json:"rating"`       // Рейтинг
	ReleaseDate string  `json:"release_date"` // Дата выхода
	Stock       int     `json:"stock"`        // Наличие на складе
	Discount    float64 `json:"discount"`     // Скидка в процентах
}

var validCoupons = map[string]float64{
	"SAVE10":     10.0,
	"DISCOUNT20": 20.0,
}

// CartItemResponse включает информацию о товаре в корзине
type CartItemResponse struct {
	ID        int     `json:"id"`
	Email     string  `json:"email"`
	ProductID int     `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Name      string  `json:"name"`
	Price     float64 `json:"price"`
	ImageURL  string  `json:"image_url"`
}

// CouponRequest структура для запроса купона
type CouponRequest struct {
	Email  string `json:"email"`
	Coupon string `json:"coupon"`
}

type OrderItem struct {
	ProductID int     `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
}

type OrderRequest struct {
	Email          string      `json:"email"`
	ShippingMethod string      `json:"shipping_method"`
	PaymentMethod  string      `json:"payment_method"`
	Address        string      `json:"address"`
	ContactInfo    string      `json:"contact_info"`
	Total          float64     `json:"total"`
	Items          []OrderItem `json:"items"`
}

type Order struct {
	ID             int     `json:"id"`
	ShippingMethod string  `json:"shipping_method"`
	PaymentMethod  string  `json:"payment_method"`
	Address        string  `json:"address"`
	ContactInfo    string  `json:"contact_info"`
	Total          float64 `json:"total"`
	CreatedAt      string  `json:"created_at"`
}

func main() {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)

	createTables(db)

	router := gin.Default()

	// CORS с динамическими origin
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Статические файлы
	router.Static("/static", "./public")
	router.Static("/images", "./images")
	router.GET("/auth.js", func(c *gin.Context) {
		c.File(filepath.Join("public", "auth.js"))
	})

	// HTML routes
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/test.html")
	})
	router.GET("/login.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "login.html"))
	})
	router.GET("/register.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "register.html"))
	})
	router.GET("/test.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "test.html"))
	})
	router.GET("/profile.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "profile.html"))
	})
	router.GET("/product.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "product.html"))
	})
	router.GET("/cart.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "cart.html"))
	})
	router.GET("/checkout.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "checkout.html"))
	})
	router.GET("/order_confirmation.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "order_confirmation.html"))
	})
	router.GET("/support.html", func(c *gin.Context) {
		c.File(filepath.Join("public", "support.html"))
	})
	// Исправленный маршрут для админ-панели
	router.GET("/admin", func(c *gin.Context) {
		c.File(filepath.Join("public", "admin_products.html"))
	})

	// API routes
	api := router.Group("/api")
	{
		api.POST("/register", registerHandler(db))
		api.POST("/login", loginHandler(db))
		api.GET("/search", searchHandler(db))
		api.GET("/health", healthCheck)
		api.POST("/change-password", changePasswordHandler(db))
		api.GET("/products", productsHandler(db))
		api.GET("/products/:id", productDetailsHandler(db))
		api.POST("/cart/add", addToCartHandler(db))
		api.PUT("/cart/update", updateCartHandler(db))
		api.DELETE("/cart/remove", removeFromCartHandler(db))
		api.GET("/cart", getCartHandler(db))
		api.POST("/cart/apply-coupon", applyCouponHandler(db))
		api.POST("/order", createOrderHandler(db))
		api.GET("/orders", getOrdersHandler(db))
		api.GET("/profile", getProfileHandler(db))
		api.POST("/log", clientLogHandler) // новый маршрут для логирования
	}

	// Внутри функции main() после инициализации маршрутов добавляем группу для админки
	adminGroup := router.Group("/admin")
	{
		// Маршрут для добавления нового товара
		adminGroup.POST("/products", addProductHandler(db))
		// Маршрут для обновления существующего товара (по ID)
		adminGroup.PUT("/products/:id", updateProductHandler(db))
		// Маршрут для удаления товара (по ID)
		adminGroup.DELETE("/products/:id", deleteProductHandler(db))
		// Маршрут для загрузки изображений/видео
		adminGroup.POST("/upload", uploadMediaHandler())
	}

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Page not found"})
	})

	log.Printf("Server running on port %d", port)
	log.Fatal(router.Run(fmt.Sprintf(":%d", port)))
}

func clientLogHandler(c *gin.Context) {
	var req struct {
		Message string `json:"message"`
		Level   string `json:"level"` // например, INFO, ERROR, WARN и т.д.
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных для лога"})
		return
	}

	// Пример: вывод в консоль
	log.Printf("CLIENT LOG [%s]: %s", req.Level, req.Message)

	// Если нужно сохранять логи в файл, можно открыть/подключить файл и записывать туда
	// Например, используя логгер с файлом:
	// logger.Println(fmt.Sprintf("CLIENT LOG [%s]: %s", req.Level, req.Message))

	c.JSON(http.StatusOK, gin.H{"status": "logged"})
}

func productDetailsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id") // Получаем ID товара из URL параметра ":id"
		productID, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
			return
		}

		// SQL-запрос для получения товара по ID
		query := "SELECT * FROM products WHERE id = ?"
		row := db.QueryRow(query, productID)

		var product Product
		err = row.Scan(
			&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL,
			&product.Platform, &product.Genre, &product.Developer, &product.Publisher,
			&product.Rating, &product.ReleaseDate, &product.Stock, &product.Discount,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
				return
			}
			log.Printf("Database query error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch product details"})
			return
		}

		c.JSON(http.StatusOK, product) // Возвращаем данные товара в формате JSON
	}
}

func createTables(db *sql.DB) {
	// Создание таблицы пользователей
	usersTableQuery := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE,
		username TEXT UNIQUE,
		password TEXT,
		registered DATETIME DEFAULT CURRENT_TIMESTAMP
	)`
	_, err := db.Exec(usersTableQuery)
	if err != nil {
		log.Fatalf("Error creating users table: %v", err)
	}

	// Создание таблицы товаров
	productsTableQuery := `CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		description TEXT,
		price REAL,
		image_url TEXT,
		platform TEXT,
		genre TEXT,
		developer TEXT,
		publisher TEXT,
		rating REAL,
		release_date TEXT,
		stock INTEGER,
		discount REAL
	)`
	_, err = db.Exec(productsTableQuery)
	if err != nil {
		log.Fatalf("Error creating products table: %v", err)
	}

	// Новая таблица для товаров в корзине
	cartItemsTableQuery := `CREATE TABLE IF NOT EXISTS cart_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT,
		product_id INTEGER,
		quantity INTEGER
	)`
	_, err = db.Exec(cartItemsTableQuery)
	if err != nil {
		log.Fatalf("Error creating cart_items table: %v", err)
	}

	// Новая таблица для хранения купонов (один купон на пользователя)
	cartCouponsTableQuery := `CREATE TABLE IF NOT EXISTS cart_coupons (
		user_email TEXT PRIMARY KEY,
		coupon TEXT
	)`
	_, err = db.Exec(cartCouponsTableQuery)
	if err != nil {
		log.Fatalf("Error creating cart_coupons table: %v", err)
	}

	// Таблица заказов
	ordersTableQuery := `CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT,
		shipping_method TEXT,
		payment_method TEXT,
		address TEXT,
		contact_info TEXT,
		total REAL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`
	_, err = db.Exec(ordersTableQuery)
	if err != nil {
		log.Fatalf("Error creating orders table: %v", err)
	}

	// Таблица товаров в заказах
	orderItemsTableQuery := `CREATE TABLE IF NOT EXISTS order_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id INTEGER,
		product_id INTEGER,
		quantity INTEGER,
		price REAL,
		FOREIGN KEY(order_id) REFERENCES orders(id)
	)`
	_, err = db.Exec(orderItemsTableQuery)
	if err != nil {
		log.Fatalf("Error creating order_items table: %v", err)
	}
}

func registerHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var newUser User
		// Предполагаем, что данные передаются в формате JSON
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}

		// Проверка на существование пользователя с таким же email или username
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? OR username = ?", newUser.Email, newUser.Username).Scan(&count)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки уникальности: " + err.Error()})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Пользователь с таким email или никнеймом уже существует"})
			return
		}

		// Хэширование пароля перед сохранением
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка шифрования пароля"})
			return
		}
		newUser.Password = string(hashedPassword)

		// Получаем московское время и форматируем его для записи в базу данных
		loc, err := time.LoadLocation("Europe/Moscow")
		if err != nil {
			loc = time.Local
		}
		newUser.Registered = time.Now().In(loc).Format("2006-01-02 15:04:05")

		// Вставляем нового пользователя в таблицу
		res, err := db.Exec("INSERT INTO users (email, username, password, registered) VALUES (?, ?, ?, ?)",
			newUser.Email, newUser.Username, newUser.Password, newUser.Registered)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка регистрации: " + err.Error()})
			return
		}
		userID, err := res.LastInsertId()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения id нового пользователя"})
			return
		}
		newUser.ID = int(userID)

		c.JSON(http.StatusOK, gin.H{"success": true, "user": newUser})
	}
}

func loginHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user struct {
			Email    string
			Username string
			Password string
		}

		err := db.QueryRow(
			"SELECT email, username, password FROM users WHERE email = ? OR username = ?",
			req.Identifier,
			req.Identifier,
		).Scan(&user.Email, &user.Username, &user.Password)

		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"user": gin.H{
				"email":    user.Email,
				"username": user.Username,
			},
		})
	}
}

func healthCheck(c *gin.Context) {
	c.String(http.StatusOK, "KIWI.store Backend is running")
}

func productsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query("SELECT * FROM products") // Извлекаем все товары из базы данных
		if err != nil {
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения товаров из базы данных: " + err.Error()})
			return
		}
		defer rows.Close()

		log.Println("SQL-запрос выполнен успешно")

		var products []Product
		for rows.Next() {
			var product Product
			err := rows.Scan(
				&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL,
				&product.Platform, &product.Genre, &product.Developer, &product.Publisher,
				&product.Rating, &product.ReleaseDate, &product.Stock, &product.Discount,
			)
			if err != nil {
				log.Printf("Ошибка сканирования строки результата: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки данных товара: " + err.Error()})
				return
			}
			products = append(products, product)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Ошибка итерации по результатам: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка итерации по товарам: " + err.Error()})
			return
		}

		log.Printf("Успешно получено товаров: %d", len(products))
		c.JSON(http.StatusOK, products)
	}
}

func searchHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")

		log.Printf("Поисковой запрос: %s", query)

		sqlQuery := `
			SELECT * FROM products
			WHERE
				name LIKE ? OR
				platform LIKE ? OR
				genre LIKE ? OR
				developer LIKE ? OR
				publisher LIKE ?
		`
		args := []interface{}{
			"%" + query + "%",
			"%" + query + "%",
			"%" + query + "%",
			"%" + query + "%",
			"%" + query + "%",
		}

		log.Printf("SQL-запрос: %s, Аргументы: %v", sqlQuery, args)

		rows, err := db.Query(sqlQuery, args...)
		if err != nil {
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка поиска"})
			return
		}
		defer rows.Close()

		var results []Product
		for rows.Next() {
			var product Product
			if err := rows.Scan(
				&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL,
				&product.Platform, &product.Genre, &product.Developer, &product.Publisher,
				&product.Rating, &product.ReleaseDate, &product.Stock, &product.Discount,
			); err != nil {
				log.Printf("Ошибка сканирования строки результата: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки результатов поиска"})
				return
			}
			results = append(results, product)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Ошибка итерации по результатам поиска: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка итерации по результатам поиска"})
			return
		}

		log.Printf("Результаты поиска: %v", results)

		c.JSON(http.StatusOK, results)
	}
}

// Функция смены пароля
func changePasswordHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// 1. Найти пользователя по email
		var user User
		err := db.QueryRow("SELECT email, password FROM users WHERE email = ?", req.Email).Scan(&user.Email, &user.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// 2. Сравнить старый пароль
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
			return
		}

		// 3. Захешировать новый пароль
		hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing new password"})
			return
		}

		// 4. Обновить пароль в базе данных
		_, err = db.Exec("UPDATE users SET password = ? WHERE email = ?", string(hashedNewPassword), req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password changed successfully"})
	}
}

// addToCartHandler добавляет товар в корзину
func addToCartHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email     string `json:"email"`
			ProductID int    `json:"product_id"`
			Quantity  int    `json:"quantity"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}
		if req.Quantity <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Количество должно быть больше 0"})
			return
		}
		// Проверяем, существует ли уже товар в корзине для данного пользователя
		var existingID int
		var existingQuantity int
		query := "SELECT id, quantity FROM cart_items WHERE user_email = ? AND product_id = ?"
		err := db.QueryRow(query, req.Email, req.ProductID).Scan(&existingID, &existingQuantity)
		if err != nil && err != sql.ErrNoRows {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
			return
		}
		if err == sql.ErrNoRows {
			// Вставляем новую запись в корзину
			_, err = db.Exec("INSERT INTO cart_items (user_email, product_id, quantity) VALUES (?, ?, ?)", req.Email, req.ProductID, req.Quantity)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления товара в корзину"})
				return
			}
		} else {
			// Обновляем количество товара
			newQuantity := existingQuantity + req.Quantity
			_, err = db.Exec("UPDATE cart_items SET quantity = ? WHERE id = ?", newQuantity, existingID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления количества товара"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар добавлен в корзину"})
	}
}

// updateCartHandler изменяет количество товара в корзине
func updateCartHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email     string `json:"email"`
			ProductID int    `json:"product_id"`
			Quantity  int    `json:"quantity"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}
		if req.Quantity < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Количество не может быть отрицательным"})
			return
		}
		if req.Quantity == 0 {
			// Удаляем товар, если количество равно 0
			_, err := db.Exec("DELETE FROM cart_items WHERE user_email = ? AND product_id = ?", req.Email, req.ProductID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления товара из корзины"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар удалён из корзины"})
			return
		}
		// Обновляем количество товара
		_, err := db.Exec("UPDATE cart_items SET quantity = ? WHERE user_email = ? AND product_id = ?", req.Quantity, req.Email, req.ProductID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления количества товара"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Количество товара обновлено"})
	}
}

// removeFromCartHandler удаляет товар из корзины
func removeFromCartHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email     string `json:"email"`
			ProductID int    `json:"product_id"`
		}

		// Проверка корректности JSON запроса
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}

		// Выполнение запроса на удаление товара из корзины
		result, err := db.Exec("DELETE FROM cart_items WHERE user_email = ? AND product_id = ?", req.Email, req.ProductID)
		if err != nil {
			log.Printf("Ошибка удаления товара из корзины: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления товара из корзины"})
			return
		}

		// Проверка, были ли удалены строки
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Ошибка при определении количества удалённых строк: %v", err)
		}

		if rowsAffected == 0 {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар не найден в корзине"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар удалён из корзины"})
	}
}

// getCartHandler возвращает содержимое корзины для пользователя
func getCartHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email не указан"})
			return
		}
		query := `
			SELECT ci.id, ci.user_email, ci.product_id, ci.quantity, p.name, p.price, p.image_url
			FROM cart_items ci
			LEFT JOIN products p ON ci.product_id = p.id
			WHERE ci.user_email = ?
		`
		rows, err := db.Query(query, email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения корзины"})
			return
		}
		defer rows.Close()
		var items []CartItemResponse
		for rows.Next() {
			var item CartItemResponse
			err := rows.Scan(&item.ID, &item.Email, &item.ProductID, &item.Quantity, &item.Name, &item.Price, &item.ImageURL)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки данных корзины"})
				return
			}
			items = append(items, item)
		}
		// Получаем информацию о применённом купоне (если он есть)
		var coupon string
		err = db.QueryRow("SELECT coupon FROM cart_coupons WHERE user_email = ?", email).Scan(&coupon)
		if err != nil && err != sql.ErrNoRows {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения купона"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"items":  items,
			"coupon": coupon,
		})
	}
}

// applyCouponHandler применяет купон к корзине
func applyCouponHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CouponRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}

		// Убираем пробелы и приводим купон к верхнему регистру
		couponCode := strings.ToUpper(strings.TrimSpace(req.Coupon))
		discount, exists := validCoupons[couponCode]
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный купон"})
			return
		}

		// Вставляем или обновляем купон для пользователя с купоном в верхнем регистре
		_, err := db.Exec("INSERT OR REPLACE INTO cart_coupons (user_email, coupon) VALUES (?, ?)", req.Email, couponCode)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка применения купона"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "Купон применён",
			"discount": discount,
		})
	}
}

func createOrderHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Начало транзакции
		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка начала транзакции: " + err.Error()})
			return
		}

		var req OrderRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса: " + err.Error()})
			return
		}

		// Преобразование способа оплаты
		var paymentMethod string
		if req.PaymentMethod == "card" {
			paymentMethod = "Картой"
		} else if req.PaymentMethod == "cash" {
			paymentMethod = "Наличкой"
		} else {
			paymentMethod = req.PaymentMethod
		}

		// Преобразование способа доставки
		var shippingMethod string
		if req.ShippingMethod == "standart" || req.ShippingMethod == "standard" {
			shippingMethod = "Стандартная доставка"
		} else if req.ShippingMethod == "express" {
			shippingMethod = "Экспресс-доставка"
		} else {
			shippingMethod = req.ShippingMethod
		}

		// Подсчет итоговой суммы заказа
		var total float64 = 0.0
		rows, err := tx.Query("SELECT ci.quantity, p.price FROM cart_items AS ci JOIN products AS p ON ci.product_id = p.id WHERE ci.user_email = ?", req.Email)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения товаров из корзины: " + err.Error()})
			return
		}
		for rows.Next() {
			var quantity int
			var price float64
			if err := rows.Scan(&quantity, &price); err != nil {
				rows.Close()
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения товаров: " + err.Error()})
				return
			}
			total += price * float64(quantity)
		}
		rows.Close()

		if total == 0 {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ваша корзина пуста или сумма заказа равна 0"})
			return
		}

		// Вставка заказа с преобразованными способами доставки и оплаты
		res, err := tx.Exec("INSERT INTO orders (user_email, shipping_method, payment_method, address, contact_info, total) VALUES (?, ?, ?, ?, ?, ?)",
			req.Email, shippingMethod, paymentMethod, req.Address, req.ContactInfo, total)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка оформления заказа: " + err.Error()})
			return
		}

		orderID, err := res.LastInsertId()
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения ID заказа: " + err.Error()})
			return
		}

		// Вставка товаров заказа
		rows2, err := tx.Query("SELECT ci.product_id, ci.quantity, p.price FROM cart_items AS ci JOIN products AS p ON ci.product_id = p.id WHERE ci.user_email = ?", req.Email)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения товаров для заказа: " + err.Error()})
			return
		}
		for rows2.Next() {
			var productID, quantity int
			var price float64
			if err := rows2.Scan(&productID, &quantity, &price); err != nil {
				rows2.Close()
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных товаров заказа: " + err.Error()})
				return
			}
			_, err = tx.Exec("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
				orderID, productID, quantity, price)
			if err != nil {
				rows2.Close()
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления товара в заказ: " + err.Error()})
				return
			}
		}
		rows2.Close()

		// Очистка корзины
		_, err = tx.Exec("DELETE FROM cart_items WHERE user_email = ?", req.Email)
		if err != nil {
			log.Printf("Ошибка очистки корзины пользователя %s: %v", req.Email, err)
		}

		// Завершение транзакции
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка завершения транзакции: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "order_id": orderID, "message": "Заказ оформлен успешно"})
	}
}

func getOrdersHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email обязательное поле"})
			return
		}
		rows, err := db.Query("SELECT id, shipping_method, payment_method, address, contact_info, total, created_at FROM orders WHERE user_email = ?", email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка запроса к базе: " + err.Error()})
			return
		}
		defer rows.Close()
		var orders []Order
		for rows.Next() {
			var order Order
			if err := rows.Scan(&order.ID, &order.ShippingMethod, &order.PaymentMethod, &order.Address, &order.ContactInfo, &order.Total, &order.CreatedAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных заказа: " + err.Error()})
				return
			}
			// Преобразование даты заказа в нужный формат
			t, err := time.Parse(time.RFC3339, order.CreatedAt)
			if err == nil {
				order.CreatedAt = t.Format("15:04 02.01.2006")
			}
			// Преобразование способа оплаты
			if order.PaymentMethod == "card" {
				order.PaymentMethod = "Картой"
			} else if order.PaymentMethod == "cash" {
				order.PaymentMethod = "Наличкой"
			}
			// Преобразование способа доставки (учитываем оба варианта "standart" и "standard")
			if order.ShippingMethod == "standart" || order.ShippingMethod == "standard" {
				order.ShippingMethod = "Стандартная доставка"
			} else if order.ShippingMethod == "express" {
				order.ShippingMethod = "Экспресс-доставка"
			}
			orders = append(orders, order)
		}
		c.JSON(http.StatusOK, orders)
	}
}

func getProfileHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Отсутствует email"})
			return
		}

		var user User
		// Предполагается, что в таблице users есть поле registered (дата регистрации)
		query := "SELECT id, email, username, registered FROM users WHERE email = ?"
		err := db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Username, &user.Registered)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных пользователя: " + err.Error()})
			}
			return
		}
		c.JSON(http.StatusOK, user)
	}
}

// addProductHandler - Добавляет новый товар (игру)
func addProductHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var prod Product
		if err := c.ShouldBindJSON(&prod); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}

		query := `INSERT INTO products 
			(name, description, price, image_url, platform, genre, developer, publisher, rating, release_date, stock, discount)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := db.Exec(query, prod.Name, prod.Description, prod.Price, prod.ImageURL,
			prod.Platform, prod.Genre, prod.Developer, prod.Publisher, prod.Rating, prod.ReleaseDate, prod.Stock, prod.Discount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления товара: " + err.Error()})
			return
		}
		id, _ := res.LastInsertId()
		prod.ID = int(id)
		c.JSON(http.StatusOK, gin.H{"success": true, "product": prod})
	}
}

// updateProductHandler - Обновляет данные товара по ID (включая цену, скидку, запас и прочее)
func updateProductHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var prod Product
		if err := c.ShouldBindJSON(&prod); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат запроса"})
			return
		}

		query := `UPDATE products SET 
			name=?, description=?, price=?, image_url=?, platform=?, genre=?, developer=?, publisher=?, rating=?, release_date=?, stock=?, discount=?
			WHERE id=?`
		if _, err := db.Exec(query, prod.Name, prod.Description, prod.Price, prod.ImageURL,
			prod.Platform, prod.Genre, prod.Developer, prod.Publisher, prod.Rating, prod.ReleaseDate, prod.Stock, prod.Discount, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления товара: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар обновлен"})
	}
}

// deleteProductHandler - Удаляет товар по ID
func deleteProductHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if _, err := db.Exec("DELETE FROM products WHERE id = ?", id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления товара: " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Товар удален"})
	}
}

// uploadMediaHandler - Обрабатывает загрузку файлов (изображений или видео)
// Файлы сохраняются в директорию "./public/uploads" и возвращается URL для доступа
func uploadMediaHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Файл не найден"})
			return
		}
		uploadPath := "./public/uploads/" + file.Filename
		if err := c.SaveUploadedFile(file, uploadPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения файла: " + err.Error()})
			return
		}
		fileURL := "/static/uploads/" + file.Filename
		c.JSON(http.StatusOK, gin.H{"success": true, "file_url": fileURL})
	}
}
