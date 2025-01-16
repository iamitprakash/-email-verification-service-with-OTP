package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
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
	Email     string    `json:"email"`
	OTP       string    `json:"otp"`
	CreatedAt time.Time `json:"created_at"`
	Attempts  int       `json:"attempts"`
	Verified  bool      `json:"verified"`
}

type EmailService interface {
	SendEmail(to, subject, body string) error
}

type RedisService interface {
	StoreOTP(record OTPRecord) error
	GetOTP(email string) (*OTPRecord, error)
	DeleteOTP(email string) error
}

// Email Service Implementation
type SMTPEmailService struct {
	dialer *gomail.Dialer
}

func NewSMTPEmailService() *SMTPEmailService {
	dialer := gomail.NewDialer(
		os.Getenv("SMTP_HOST"),
		587, // default SMTP port
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

// Redis Service Implementation
type RedisOTPService struct {
	client *redis.Client
}

func NewRedisOTPService() *RedisOTPService {
	client := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_URL"),
	})
	
	return &RedisOTPService{client: client}
}

func (s *RedisOTPService) StoreOTP(record OTPRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("email_verification:%s", record.Email)
	return s.client.Set(s.client.Context(), key, string(data), time.Minute*OTPExpiryMinutes).Err()
}

func (s *RedisOTPService) GetOTP(email string) (*OTPRecord, error) {
	key := fmt.Sprintf("email_verification:%s", email)
	data, err := s.client.Get(s.client.Context(), key).Result()
	if err != nil {
		return nil, err
	}

	var record OTPRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return nil, err
	}

	return &record, nil
}

func (s *RedisOTPService) DeleteOTP(email string) error {
	key := fmt.Sprintf("email_verification:%s", email)
	return s.client.Del(s.client.Context(), key).Err()
}

// Verification Service
type VerificationService struct {
	emailService EmailService
	redisService RedisService
}

func NewVerificationService(emailService EmailService, redisService RedisService) *VerificationService {
	return &VerificationService{
		emailService: emailService,
		redisService: redisService,
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
	// Check for existing OTP
	existingRecord, err := s.redisService.GetOTP(email)
	if err == nil && existingRecord != nil {
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
	if err := s.redisService.StoreOTP(record); err != nil {
		return err
	}

	// Send email
	if err := s.emailService.SendEmail(
		email,
		"Email Verification Code",
		getOTPEmailTemplate(otp),
	); err != nil {
		s.redisService.DeleteOTP(email)
		return err
	}

	return nil
}

func (s *VerificationService) VerifyOTP(email, providedOTP string) error {
	record, err := s.redisService.GetOTP(email)
	if err != nil {
		return fmt.Errorf("no verification code found or code has expired")
	}

	if record.Verified {
		return fmt.Errorf("email is already verified")
	}

	if record.Attempts >= MaxAttempts {
		s.redisService.DeleteOTP(email)
		return fmt.Errorf("maximum verification attempts exceeded")
	}

	record.Attempts++

	if record.OTP != providedOTP {
		s.redisService.StoreOTP(*record)
		return fmt.Errorf("invalid verification code")
	}

	record.Verified = true
	return s.redisService.StoreOTP(*record)
}

// HTTP Handlers
func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	app := fiber.New()

	emailService := NewSMTPEmailService()
	redisService := NewRedisOTPService()
	verificationService := NewVerificationService(emailService, redisService)

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
