package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"

	"gopkg.in/natefinch/lumberjack.v2"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func initLogger() {
	log.SetOutput(&lumberjack.Logger{
		Filename:   "./logs/api.log",
		MaxSize:    1,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   false,
	})
}

func JSONLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.WithFields(log.Fields{
			"ip":     c.ClientIP(),
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"status": c.Writer.Status(),
		}).Info("요청 수신")
		c.Next()
	}
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	initLogger()
	router.Use(JSONLogger())
	log.Info("서버 시작")

	auth := router.Group("/api/auth")
	{
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}
			Username := strings.TrimSpace(request.Username)
			Name := strings.TrimSpace(request.Name)
			Email := strings.TrimSpace(request.Email)
			Phone := strings.TrimSpace(request.Phone)
			Password := strings.TrimSpace(request.Password)

			if Username == "" || Name == "" || Email == "" || Phone == "" || Password == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "all fields are required"})
				return
			}

			_, err := store.db.Exec("INSERT INTO users (username, name, email, phone, password) VALUES (?, ?, ?, ?, ?)",
				Username,
				Name,
				Email,
				Phone,
				Password,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create user"})
				return
			}

			c.JSON(http.StatusAccepted, gin.H{

				"user": gin.H{
					"username": request.Username,
					"name":     request.Name,
					"email":    request.Email,
					"phone":    request.Phone,
				},
			})
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username) // 반환값: 사용자, 있는지 여부, 에러 여부
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "logout completed",
			})
		})

		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			// db 삭제 후 세션 삭제
			if sessions.tokens[token].Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "wrong password"})
				return
			}
			_, err := store.db.Exec("DELETE FROM users WHERE password = ?", request.Password)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete account"})
				return
			}
			sessions.delete(token)
			clearAuthorizationCookie(c)

			c.JSON(http.StatusAccepted, gin.H{
				"message": "회원 삭제 완료",
				"user":    makeUserResponse(user),
			})
		})
	}

	protected := router.Group("/api") // db에서 셀렉 or 로깅 등
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "입금 금액은 0보다 커야 합니다"})
				return
			}
			_, err := store.db.Exec("UPDATE users SET balance = balance + ? WHERE id = ?", request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update balance"})
				return
			}
			updatedUser, _, err := store.findUserByUsername(user.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load updated user"})
				return
			}
			sessions.tokens[token] = updatedUser

			c.JSON(http.StatusOK, gin.H{
				"message": "입금 완료",
				"user":    makeUserResponse(updatedUser),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "출금 금액은 0보다 커야 합니다"})
				return
			}

			if user.Balance < request.Amount {
				c.JSON(http.StatusBadRequest, gin.H{"message": "돈이 부족함"})
				return
			}

			_, err := store.db.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update balance"})
				return
			}
			updatedUser, _, err := store.findUserByUsername(user.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load updated user"})
				return
			}
			sessions.tokens[token] = updatedUser

			c.JSON(http.StatusOK, gin.H{
				"message": "출금 완료",
				"user":    makeUserResponse(updatedUser),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if user.Balance < request.Amount {
				c.JSON(http.StatusBadRequest, gin.H{"message": "돈이 부족함"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "이체 금액은 0보다 커야 합니다"})
				return
			}

			_, ok, err := store.findUserByUsername(request.ToUsername) // 반환값: 사용자, 있는지 여부, 에러 여부
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "그런 사용자 없음"})
				return
			}

			// 시작
			tx, err := store.db.Begin()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to start transaction"})
				return
			}
			defer tx.Rollback()

			_, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update sender balance"})
				return
			}

			_, err = tx.Exec("UPDATE users SET balance = balance + ? WHERE username = ?", request.Amount, request.ToUsername)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update recipient balance"})
				return
			}

			err = tx.Commit()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to commit transaction"})
				return
			}

			updatedUser, _, err := store.findUserByUsername(user.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load updated user"})
				return
			}
			sessions.tokens[token] = updatedUser

			c.JSON(http.StatusOK, gin.H{
				"message": "송금이 완료됨",
				"user":    makeUserResponse(updatedUser),
				"target":  request.ToUsername,
				"amount":  request.Amount,
			})
		})

		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			result, err := store.db.Query("SELECT id, title, content, owner_id, created_at, updated_at FROM posts")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to query posts"})
				return
			}
			defer result.Close()

			var posts []PostView

			for result.Next() {
				var post PostView
				err = result.Scan(&post.ID, &post.Title, &post.Content, &post.OwnerID, &post.CreatedAt, &post.UpdatedAt)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to scan post"})
					return
				}
				posts = append(posts, post)
			}

			c.JSON(http.StatusOK, PostListResponse{
				Posts: posts,
			})
		})

		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			now := time.Now().Format(time.RFC3339)

			Title := strings.TrimSpace(request.Title)
			Content := strings.TrimSpace(request.Content)
			if Title == "" || Content == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "title and content cannot be empty"})
				return
			}

			_, err := store.db.Exec("INSERT INTO posts (title, content, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", Title, Content, user.ID, now, now)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create post"})
				return
			}

			var postID uint
			err = store.db.QueryRow("SELECT last_insert_rowid()").Scan(&postID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to retrieve created post"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "게시글이 생성됨",
				"post": PostView{
					ID:          postID,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			var_id := c.Param("id")
			var post PostView
			err := store.db.QueryRow("SELECT id, title, content, owner_id, created_at, updated_at FROM posts WHERE id = ?", var_id).Scan(&post.ID, &post.Title, &post.Content, &post.OwnerID, &post.CreatedAt, &post.UpdatedAt)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to query post"})
				return
			}

			c.JSON(http.StatusOK, PostResponse{
				Post: post,
			})
		})

		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			now := time.Now().Format(time.RFC3339)

			var ownerID uint
			err := store.db.QueryRow("SELECT owner_id FROM posts WHERE id = ?", c.Param("id")).Scan(&ownerID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to query post owner"})
				return
			}
			if ownerID != user.ID {
				c.JSON(http.StatusForbidden, gin.H{"message": "당신은 이 게시글의 소유자가 아닙니다"})
				return
			}

			_, err = store.db.Exec("UPDATE posts SET title = ?, content = ?, updated_at = ? WHERE id = ?", strings.TrimSpace(request.Title), strings.TrimSpace(request.Content), now, c.Param("id"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update post"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "수정 완료",
				"post": PostView{
					Title:     strings.TrimSpace(request.Title),
					Content:   strings.TrimSpace(request.Content),
					OwnerID:   user.ID,
					UpdatedAt: now,
				},
			})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			var ownerID uint
			err := store.db.QueryRow("SELECT owner_id FROM posts WHERE id = ?", c.Param("id")).Scan(&ownerID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to query post owner"})
				return
			}

			user_ID := sessions.tokens[token].ID
			if ownerID != user_ID {
				c.JSON(http.StatusForbidden, gin.H{"message": "당신은 이 게시글의 소유자가 아닙니다"})
				return
			}

			_, err = store.db.Exec("DELETE FROM posts WHERE id = ?", c.Param("id"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete post"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "삭제 완료",
			})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
