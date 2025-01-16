```bash
go mod init emailverification
go get github.com/gofiber/fiber/v2
go get github.com/joho/godotenv
go get gopkg.in/gomail.v2
go get github.com/denisenkom/go-mssqldb
```

```bash
SMTP_HOST=smtp.example.com
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
```

```bash
DB_SERVER=your-server
DB_PORT=1433
DB_USER=your-username
DB_PASSWORD=your-password
DB_NAME=your-database
```
