package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
	_ "github.com/denisenkom/go-mssqldb"
)

// Constants
const (
	OTPLength         = 6
	OTPExpiryMinutes  = 10
	MaxAttempts       = 3
	ResendDelayMins   = 1
)

// Types
type OTPRecord struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	OTP       string    `json:"otp"`
	CreatedAt time.Time `json:"created_at"`
	Attempts  int       `json:"attempts"`
	Verified  bool      `json:"verified"`
}

type EmailService interface {
	SendEmail(to, subject, body string) error
}

type DBService interface {
	StoreOTP(record OTPRecord) error
	GetOTP(email string) (*OTPRecord, error)
	UpdateOTP(record OTPRecord) error
	CleanupExpiredOTPs() error
}

// Database schema setup
const schemaSQL = `
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='otp_verifications' and xtype='U')
CREATE TABLE otp_verifications (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(10) NOT NULL,
    created_at DATETIME NOT NULL,
    attempts INT DEFAULT 0,
    verified BIT DEFAULT 0,
    CONSTRAINT UC_Email UNIQUE (email)
)
`

// Email Service Implementation
type SMTPEmailService struct {
	dialer *gomail.Dialer
}

func NewSMTPEmailService() *SMTPEmailService {
	dialer := gomail.NewDialer(
		os.Getenv("SMTP_HOST"),
		587,
		os.Getenv("SMTP_USER"),
		os.Getenv("SMTP_PASS"),
	)
	return &SMTPEmailService{dialer: dialer}
}

func (s *SMTPEmailService) SendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_FROM"))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)
	return s.dialer.DialAndSend(m)
}

// SQL Server Implementation
type SQLServerService struct {
	db *sql.DB
}

func NewSQLServerService() (*SQLServerService, error) {
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%s;database=%s",
		os.Getenv("DB_SERVER"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	db, err := sql.Open("mssql", connString)
	if err != nil {
		return nil, err
	}

	// Create schema if not exists
	if _, err := db.Exec(schemaSQL); err != nil {
		return nil, err
	}

	return &SQLServerService{db: db}, nil
}

func (s *SQLServerService) StoreOTP(record OTPRecord) error {
	query := `
		MERGE INTO otp_verifications WITH (HOLDLOCK) AS target
		USING (SELECT @Email AS email) AS source
		ON target.email = source.email
		WHEN MATCHED THEN
			UPDATE SET 
				otp = @OTP,
				created_at = @CreatedAt,
				attempts = @Attempts,
				verified = @Verified
		WHEN NOT MATCHED THEN
			INSERT (email, otp, created_at, attempts, verified)
			VALUES (@Email, @OTP, @CreatedAt, @Attempts, @Verified);
	`

	_, err := s.db.Exec(query,
		sql.Named("Email", record.Email),
		sql.Named("OTP", record.OTP),
		sql.Named("CreatedAt", record.CreatedAt),
		sql.Named("Attempts", record.Attempts),
		sql.Named("Verified", record.Verified),
	)
	return err
}

func (s *SQLServerService) GetOTP(email string) (*OTPRecord, error) {
	query := `
		SELECT id, email, otp, created_at, attempts, verified 
		FROM otp_verifications 
		WHERE email = @Email
	`

	var record OTPRecord
	err := s.db.QueryRow(query, sql.Named("Email", email)).Scan(
		&record.ID,
		&record.Email,
		&record.OTP,
		&record.CreatedAt,
		&record.Attempts,
		&record.Verified,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (s *SQLServerService) UpdateOTP(record OTPRecord) error {
	query := `
		UPDATE otp_verifications 
		SET attempts = @Attempts, verified = @Verified 
		WHERE email = @Email
	`

	_, err := s.db.Exec(query,
		sql.Named("Attempts", record.Attempts),
		sql.Named("Verified", record.Verified),
		sql.Named("Email", record.Email),
	)
	return err
}

func (s *SQLServerService) CleanupExpiredOTPs() error {
	query := `
		DELETE FROM otp_verifications 
		WHERE created_at < DATEADD(MINUTE, -@ExpiryMinutes, GETDATE())
		AND verified = 0
	`

	_, err := s.db.Exec(query, sql.Named("ExpiryMinutes", OTPExpiryMinutes))
	return err
}

// Verification Service
type VerificationService struct {
	emailService EmailService
	dbService    DBService
}

func NewVerificationService(emailService EmailService, dbService DBService) *VerificationService {
	return &VerificationService{
		emailService: emailService,
		dbService:    dbService,
	}
}

func generateOTP() string {
	const digits = "0123456789"
	otp := make([]byte, OTPLength)
	for i := range otp {
		otp[i] = digits[time.Now().UnixNano()%int64(len(digits))]
	}
	return string(otp)
}

func getOTPEmailTemplate(otp string) string {
	return fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
			<h2>Email Verification</h2>
			<p>Your verification code is:</p>
			<h1 style="font-size: 32px; letter-spacing: 8px; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 4px;">
				%s
			</h1>
			<p>This code will expire in %d minutes.</p>
			<p>If you didn't request this code, please ignore this email.</p>
		</div>
	`, otp, OTPExpiryMinutes)
}

func (s *VerificationService) SendVerificationEmail(email string) error {
	// Cleanup expired OTPs
	s.dbService.CleanupExpiredOTPs()

	// Check for existing OTP
	existingRecord, err := s.dbService.GetOTP(email)
	if err != nil {
		return err
	}

	if existingRecord != nil {
		timeSinceLastOTP := time.Since(existingRecord.CreatedAt).Minutes()
		if timeSinceLastOTP < ResendDelayMins {
			return fmt.Errorf("please wait %d minutes before requesting a new OTP", ResendDelayMins)
		}
	}

	// Generate new OTP
	otp := generateOTP()
	record := OTPRecord{
		Email:     email,
		OTP:       otp,
		CreatedAt: time.Now(),
		Attempts:  0,
		Verified:  false,
	}

	// Store OTP
	if err := s.dbService.StoreOTP(record); err != nil {
		return err
	}

	// Send email
	return s.emailService.SendEmail(
		email,
		"Email Verification Code",
		getOTPEmailTemplate(otp),
	)
}

func (s *VerificationService) VerifyOTP(email, providedOTP string) error {
	record, err := s.dbService.GetOTP(email)
	if err != nil {
		return err
	}

	if record == nil {
		return fmt.Errorf("no verification code found or code has expired")
	}

	if record.Verified {
		return fmt.Errorf("email is already verified")
	}

	if record.Attempts >= MaxAttempts {
		return fmt.Errorf("maximum verification attempts exceeded")
	}

	record.Attempts++

	if record.OTP != providedOTP {
		if err := s.dbService.UpdateOTP(*record); err != nil {
			return err
		}
		return fmt.Errorf("invalid verification code")
	}

	record.Verified = true
	return s.dbService.UpdateOTP(*record)
}

// HTTP Server Setup
func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize services
	emailService := NewSMTPEmailService()
	dbService, err := NewSQLServerService()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	verificationService := NewVerificationService(emailService, dbService)

	app := fiber.New()

	app.Post("/send-otp", func(c *fiber.Ctx) error {
		var body struct {
			Email string `json:"email"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Invalid request body",
			})
		}

		if err := verificationService.SendVerificationEmail(body.Email); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Verification code sent",
		})
	})

	app.Post("/verify-otp", func(c *fiber.Ctx) error {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Invalid request body",
			})
		}

		if err := verificationService.VerifyOTP(body.Email, body.OTP); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Email verified successfully",
		})
	})

	log.Fatal(app.Listen(":3000"))
}
