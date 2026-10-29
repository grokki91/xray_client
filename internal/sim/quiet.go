package sim

import (
	"io"
	"log"
)

// quietLog — маска ругается на каждое прерванное клиентом рукопожатие; в тестах это шум.
func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }
