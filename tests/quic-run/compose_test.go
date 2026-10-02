//go:build d2k_donor

package quicprobe

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestD2KComposeParity runs the unchanged donor compose (questions.go) on the
// property combinations that reach it without a FakeAhead arm and compares the
// resulting zapret actions with the C plan composed from the same properties.
// Both sides are reduced to the actions that reach the wire: in zapret a DROP
// verdict is sticky (nfq2/desync.c verdict_aggregate), so udplen placed after
// `send:ipfrag … drop` changes nothing on the wire.
func TestD2KComposeParity(t *testing.T) {
	const junk = "--lua-desync=fake:payload=quic_initial:dir=out:blob=0x00000000000000000000000000000000:repeats=2"
	const udplen = "--lua-desync=udplen:payload=quic_initial:dir=out:increment=100"
	frags := []string{"", "ipfrag pos=8", "ipfrag pos=8 обратный порядок", "z2k_ipfrag3_tiny", "z2k_ipfrag3"}
	type sc struct {
		junk, longer bool
		frag         int
		want         string // exact donor Strategy
	}
	cases := []sc{
		{junk: true, want: junk},
		{longer: true, want: udplen},
		{junk: true, longer: true, want: junk + " " + udplen},
		{},
	}
	for f := 1; f <= 4; f++ {
		line := fragArmLine(frags[f]) + " --lua-desync=drop"
		cases = append(cases,
			sc{frag: f, longer: true, want: line + " " + udplen},
			sc{frag: f, junk: true, want: junk + " " + line},
			sc{frag: f, junk: true, longer: true, want: junk + " " + line + " " + udplen})
	}
	for _, c := range cases {
		var res Result
		res.Props.JunkAheadHelps = boolp(c.junk)
		if c.longer {
			res.Props.UDPLen = 100
		}
		if c.frag > 0 {
			res.Props.FragArm = frags[c.frag]
			res.Props.FragSurvives = boolp(true)
		}
		compose(&res)
		if res.Strategy != c.want {
			t.Fatalf("donor compose %+v = %q, baseline %q", c, res.Strategy, c.want)
		}
		plain := ""
		for _, profile := range []int{0, 1} {
			out, err := exec.Command(os.Getenv("D2K_QUIC_RUN_BIN"), "--compose",
				b01(c.junk), b01(c.longer), strconv.Itoa(profile), strconv.Itoa(c.frag)).CombinedOutput()
			if err != nil {
				t.Fatalf("C compose %+v: %v %s", c, err, out)
			}
			got := cWire(string(out))
			want := donorWire(res.Strategy, frags)
			if got != want {
				t.Fatalf("compose %+v profile=%d: donor wire %q, C wire %q\nC plan:\n%s", c, profile, want, got, out)
			}
			// Provenance is journal/trace data, never plan text: the plan ID
			// is a hash of the whole text.
			if profile == 0 {
				plain = string(out)
			} else if string(out) != plain || strings.Contains(plain, "PROFILE") {
				t.Fatalf("compose %+v: PROFILE provenance changed plan text\n%s\n---\n%s", c, plain, out)
			}
		}
	}
}

func b01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// donorWire reduces a donor strategy to wire actions: fake blob/copies/ttl,
// fragment shape, udplen increment (only while the packet is not dropped).
func donorWire(s string, frags []string) string {
	var acts []string
	dropped := false
	for _, a := range strings.Fields(s) {
		a = strings.TrimPrefix(a, "--lua-desync=")
		switch {
		case strings.HasPrefix(a, "fake:"):
			blob, reps, ttl := "", "1", "0"
			for _, kv := range strings.Split(a, ":")[1:] {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "blob":
					blob = strings.TrimPrefix(v, "0x")
				case "repeats":
					reps = v
				case "ip_ttl":
					ttl = v
				}
			}
			acts = append(acts, fmt.Sprintf("fake %s x%s ttl=%s", blob, reps, ttl))
		case strings.HasPrefix(a, "send:"):
			shape := 0
			for i := 1; i < len(frags); i++ {
				if "--lua-desync="+a == fragArmLine(frags[i]) {
					shape = i
				}
			}
			acts = append(acts, fmt.Sprintf("ipfrag %d", shape))
		case a == "drop":
			dropped = true
		case strings.HasPrefix(a, "udplen:"):
			if !dropped {
				_, inc, _ := strings.Cut(a, "increment=")
				acts = append(acts, "udplen "+inc)
			}
		default:
			acts = append(acts, "unknown "+a)
		}
	}
	if len(acts) == 0 {
		return "none"
	}
	return strings.Join(acts, "; ")
}

// cWire reduces a C plan text to the same wire actions.
func cWire(plan string) string {
	if strings.TrimSpace(plan) == "none" {
		return "none"
	}
	var acts []string
	blob, ttl := "", "0"
	for _, line := range strings.Split(plan, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "payload":
			blob = f[2]
		case "poison":
			for _, kv := range f[2:] {
				if v, ok := strings.CutPrefix(kv, "ttl="); ok {
					ttl = v
				}
			}
		case "fake":
			reps := ""
			for _, kv := range f[1:] {
				if v, ok := strings.CutPrefix(kv, "repeats="); ok {
					reps = v
				}
			}
			acts = append(acts, fmt.Sprintf("fake %s x%s ttl=%s", blob, reps, ttl))
		case "ipfrag":
			acts = append(acts, "ipfrag "+f[1])
		case "udplen":
			acts = append(acts, "udplen "+f[1])
		}
	}
	// Plan text lists the fragment shape in its header block, before the fake;
	// the wire order is fake, fragments, so order by action kind.
	order := map[string]int{"fake": 0, "ipfrag": 1, "udplen": 2}
	for i := 1; i < len(acts); i++ {
		for j := i; j > 0 && order[strings.Fields(acts[j])[0]] < order[strings.Fields(acts[j-1])[0]]; j-- {
			acts[j], acts[j-1] = acts[j-1], acts[j]
		}
	}
	if len(acts) == 0 {
		return "none"
	}
	return strings.Join(acts, "; ")
}
