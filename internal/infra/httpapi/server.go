package httpapi

import (
	"log/slog"
	"net/http"
	"time"
)

const readHeaderTimeout = 10 * time.Second

func NewServer(addr string, handler http.Handler) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		Protocols:         &protocols,
		ReadHeaderTimeout: readHeaderTimeout,
		// net/http reports its own failures (a broken connection, a panic in a
		// handler) through this logger, so it goes to the same structured
		// stream as everything else.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
}
