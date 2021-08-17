package config

import "time"

type Config struct {
	Closeips       []string
	Protectedports []string
	Every          time.Duration
	DropOrReject   string
}
