//go:build d2k_donor

// The ORIGINAL Run executes unchanged, including its actual UDP transport.
package quicprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

type localScenario struct {
	port int
	stop func()
}

// Authenticated Initial oracle, NOT an HTTP/3/application server. Both
// instruments ask whether the Initial has an authenticated response here.
func initialAnswer(packet []byte) (target bool, answer []byte, err error) {
	// Synthetic CRYPTO handshake data is sufficient for the original probe's
	// protocol oracle. It must never be reported as application acceptance.
	return initialAnswerFrame(packet, append([]byte{6, 0, 4, 2, 0, 0, 0}, make([]byte, 20)...))
}

// closeFrame is a transport CONNECTION_CLOSE with no CRYPTO, padded so the
// header-protection sample exists. The original counts any decrypted Initial
// as an answer (parse.go:72-74), whatever its frames.
var closeFrame = append([]byte{0x1c, 0, 0, 0}, make([]byte, 20)...)

func initialAnswerFrame(packet, frame []byte) (target bool, answer []byte, err error) {
	if len(packet) < 50 || packet[5] != 8 || packet[14] != 8 {
		return false, nil, fmt.Errorf("unexpected Initial shape")
	}
	dcid, scid := packet[6:14], packet[15:23]
	client, server, err := deriveKeys(dcid, V1)
	if err != nil {
		return false, nil, err
	}
	q := 23
	tok, w := readVarint(packet[q:])
	if w == 0 || tok != 0 {
		return false, nil, fmt.Errorf("token")
	}
	q += w
	n, w := readVarint(packet[q:])
	if w == 0 {
		return false, nil, fmt.Errorf("length")
	}
	q += w
	if q+int(n) != len(packet) {
		return false, nil, fmt.Errorf("length mismatch")
	}
	p := append([]byte(nil), packet...)
	if err = applyHeaderProtection(p, client.hp, q, 4, true); err != nil {
		return false, nil, err
	}
	if p[0]&3 != 3 {
		return false, nil, fmt.Errorf("expected PNLen=4 for original input")
	}
	pn := binary.BigEndian.Uint32(p[q:])
	body, err := open(client, p[q+4:], p[:q+4], pn)
	if err != nil {
		return false, nil, err
	}
	target = bytes.Contains(body, []byte("blocked.example"))
	h := []byte{0xc3, 0, 0, 0, 1, 8}
	h = append(h, scid...)
	h = append(h, 8)
	h = append(h, dcid...)
	h = appendVarint(h, 0)
	h = appendVarint(h, uint64(4+len(frame)+16))
	pnOff := len(h)
	h = append(h, 0, 0, 0, 0)
	ct, err := seal(server, frame, h, 0)
	if err != nil {
		return false, nil, err
	}
	answer = append(h, ct...)
	err = applyHeaderProtection(answer, server.hp, pnOff, 4, true)
	return target, answer, err
}

func startScenario(t *testing.T, mode string) localScenario {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if mode == "closed" {
		c.Close()
		return localScenario{port, func() {}}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		baseSeen, targetSeen := 0, 0
		for {
			b := make([]byte, 2048)
			n, addr, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			b = b[:n]
			if mode == "clear" || mode == "partial_base" || mode == "direct_flaky" {
				target, reply, err := initialAnswer(b)
				if err != nil {
					t.Errorf("oracle request: %v", err)
					continue
				}
				if target {
					targetSeen++
				} else {
					baseSeen++
				}
				if mode == "partial_base" && !target && baseSeen > 1 {
					continue
				}
				if mode == "direct_flaky" && target && targetSeen > 1 {
					continue
				}
				_, _ = c.WriteToUDP(reply, addr)
				continue
			}
			if mode != "vn_only" || n < 23 || binary.BigEndian.Uint32(b[1:5]) == 1 {
				continue
			}
			dl := int(b[5])
			if 6+dl >= len(b) {
				continue
			}
			sl := int(b[6+dl])
			if 7+dl+sl > len(b) {
				continue
			}
			// Valid VN: return the request SCID as DCID and DCID as SCID.
			reply := []byte{0x80, 0, 0, 0, 0, byte(sl)}
			reply = append(reply, b[7+dl:7+dl+sl]...)
			reply = append(reply, byte(dl))
			reply = append(reply, b[6:6+dl]...)
			reply = append(reply, 0, 0, 0, 1)
			_, _ = c.WriteToUDP(reply, addr)
		}
	}()
	return localScenario{port, func() { c.Close(); <-done }}
}

func TestD2KRunTerminalParity(t *testing.T) {
	bin := os.Getenv("D2K_QUIC_RUN_BIN")
	if bin == "" {
		t.Fatal("D2K_QUIC_RUN_BIN required")
	}
	for _, mode := range []string{"closed", "silent", "vn_only", "clear", "partial_base", "direct_flaky"} {
		t.Run(mode, func(t *testing.T) {
			ref := startScenario(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			want := Run(ctx, "blocked.example", Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(ref.port)), AllowLoopback: true, Port: ref.port, Repeats: 3, Timeout: 40 * time.Millisecond})
			cancel()
			ref.stop()
			// Explicit expected donor result ensures a broken lab cannot make
			// both implementations agree for the wrong reason.
			expected := VerdictNoQUIC
			probes := 6
			if mode == "silent" {
				expected = VerdictAddress
			}
			if mode == "closed" {
				probes = 3
			}
			if mode == "clear" || mode == "partial_base" {
				expected = VerdictClear
			}
			if mode == "direct_flaky" {
				expected = VerdictFlaky
			}
			if want.Verdict != expected || want.Probes != probes {
				t.Fatalf("donor scenario failed: %+v", want)
			}
			port := startScenario(t, mode)
			defer port.stop()
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, bin, strconv.Itoa(port.port)).Output()
			if err != nil {
				t.Fatal(err)
			}
			got := strings.TrimSpace(string(out))
			expectedText := fmt.Sprintf("%s %d", want.Verdict, want.Probes)
			if got != expectedText {
				t.Fatalf("donor=%q C=%q; donor trace=%+v", expectedText, got, want.Trace)
			}
		})
	}
}

// Unauthenticated replies the original accepts (parse.go:110-122): Retry for
// our version with an unchecked (zero) integrity tag, and VN by version 0.
func retryReply(packet []byte) []byte {
	r := []byte{0xf0, 0, 0, 0, 1, 8}
	r = append(r, packet[15:23]...)
	r = append(r, 8, 1, 2, 3, 4, 5, 6, 7, 8, 'T', 'O', 'K')
	return append(r, make([]byte, 16)...)
}

func vnReply(packet []byte) []byte {
	r := []byte{0x80, 0, 0, 0, 0, 8}
	r = append(r, packet[15:23]...)
	r = append(r, 8)
	r = append(r, packet[6:14]...)
	return append(r, 0, 0, 0, 1)
}

// Scenarios for the reply criterion and refusal handling (plan
// 2026-10-02-review-fixes, task 10). Non-Initial datagrams (fakes) and
// reshaped questions the oracle cannot parse stay unanswered.
func startReplyScenario(t *testing.T, mode string) localScenario {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		controls := 0
		for {
			b := make([]byte, 2048)
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			b = b[:n]
			target, reply, e := initialAnswer(b)
			if e != nil {
				continue
			}
			switch mode {
			case "close":
				if target {
					_, reply, e = initialAnswerFrame(b, closeFrame)
					if e != nil {
						continue
					}
				}
			case "retry", "ctl_vn":
				if target {
					continue
				}
				reply = retryReply(b)
				if mode == "ctl_vn" {
					reply = vnReply(b)
				}
			case "close_after_ctl":
				if target {
					continue
				}
			}
			_, _ = c.WriteToUDP(reply, a)
			if mode == "close_after_ctl" && !target {
				controls++
				if controls == 3 {
					c.Close() // port closed: everything after gets ICMP port unreachable
					return
				}
			}
		}
	}()
	return localScenario{c.LocalAddr().(*net.UDPAddr).Port, func() { c.Close(); <-done }}
}

func TestD2KReplyParity(t *testing.T) {
	bin := os.Getenv("D2K_QUIC_RUN_BIN")
	if bin == "" {
		t.Fatal("D2K_QUIC_RUN_BIN required")
	}
	donorBlobs(t)
	for _, mode := range []string{"close", "close_after_ctl", "retry", "ctl_vn"} {
		t.Run(mode, func(t *testing.T) {
			ref := startReplyScenario(t, mode)
			opt := Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(ref.port)), AllowLoopback: true,
				Port: ref.port, Repeats: 3, Timeout: 40 * time.Millisecond}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			want := Run(ctx, "blocked.example", opt)
			cancel()
			ref.stop()
			var args []string
			var expected string
			switch mode {
			case "close":
				if want.Verdict != VerdictClear || want.Probes != 6 {
					t.Fatalf("donor scenario failed: %+v", want)
				}
				expected = fmt.Sprintf("%s %d\n", want.Verdict, want.Probes)
			case "close_after_ctl":
				if want.Verdict != VerdictContent || want.Probes != 9 || want.Props.ResidualBlocking == nil ||
					!*want.Props.ResidualBlocking {
					t.Fatalf("donor scenario failed: %+v", want)
				}
				expected = fmt.Sprintf("%s %d\n", want.Verdict, want.Probes)
			default:
				if want.Verdict != VerdictContent || want.Props.ResidualBlocking == nil ||
					*want.Props.ResidualBlocking {
					t.Fatalf("donor scenario failed: %+v", want)
				}
				args = []string{"content"}
				expected = fmt.Sprintf("%s 1 %s %d %d\n", want.Verdict,
					want.Props.FakeAhead, want.Props.FakeRepeats, want.Props.FakeTTL)
			}
			local := startReplyScenario(t, mode)
			defer local.stop()
			out, err := exec.Command(bin, append([]string{strconv.Itoa(local.port)}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("C: %v %s", err, out)
			}
			if string(out) != expected {
				t.Fatalf("donor=%q C=%q; donor trace=%+v", expected, out, want.Trace)
			}
		})
	}
}
