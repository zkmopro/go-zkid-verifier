package smtroot

import (
	"fmt"
	"log"
	"strings"
)

// Logger emits one structured log line per call. Implementations must be
// goroutine-safe.
type Logger interface {
	Event(level, event string, kv ...any)
}

// DefaultLogger writes `level=... event=... k=v k=v` to the stdlib log.
type DefaultLogger struct{}

func (DefaultLogger) Event(level, event string, kv ...any) {
	var b strings.Builder
	fmt.Fprintf(&b, "level=%s event=%s", level, event)
	for i := 0; i+1 < len(kv); i += 2 {
		k := fmt.Sprint(kv[i])
		v := fmt.Sprint(kv[i+1])
		fmt.Fprintf(&b, " %s=%s", k, quoteIfNeeded(v))
	}
	log.Println(b.String())
}

func quoteIfNeeded(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " \t\"=") {
		return fmt.Sprintf("%q", v)
	}
	return v
}
