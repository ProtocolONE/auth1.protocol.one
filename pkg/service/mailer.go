package service

import (
	"crypto/tls"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"gopkg.in/gomail.v2"
)

// MailerInterface describes of methods for the mailer.
type MailerInterface interface {
	// Send sends mail for the specified email address with the specified header and content.
	Send(to, subject, body string) error
}

// Mailer is the mailer service.
type Mailer struct {
	replyTo string
	from    string
	dialer  *gomail.Dialer
}

// NewMailer return new mailer service.
func NewMailer(config *config.Mailer) (mailer MailerInterface) {
	dialer := gomail.NewDialer(config.Host, config.Port, config.Username, config.Password)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}
	mailer = &Mailer{config.ReplyTo, config.From, dialer}
	return
}

func (mailer *Mailer) Send(to, subject, body string) (err error) {
	m := gomail.NewMessage()
	m.SetHeader("From", mailer.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	if mailer.replyTo != "" {
		m.SetHeader("ReplyTo", mailer.replyTo)
	}
	m.SetBody("text/html", body)

	return mailer.dialer.DialAndSend(m)
}
