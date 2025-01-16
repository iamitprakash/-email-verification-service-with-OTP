```bash
go mod init emailverification
go get github.com/go-redis/redis/v8
go get github.com/gofiber/fiber/v2
go get github.com/joho/godotenv
go get gopkg.in/gomail.v2
```

```
SMTP_HOST=smtp.example.com
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
REDIS_URL=localhost:6379
``
