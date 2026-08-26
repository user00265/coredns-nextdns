package nextdns

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if any test leaves a goroutine behind. Device
// discovery detaches goroutines from the query that triggered them, which is
// exactly the shape that leaks if the shutdown path is wrong.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// net/http keeps its idle-connection reaper alive for the process.
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
