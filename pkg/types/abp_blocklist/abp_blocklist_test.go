package abp_blocklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testList = `! Title: Test list
! Version: 42
||ads.example^
@@||ok.ads.example^
||tracker.example^$important
@@||tracker.example^
@@||vip.tracker.example^$important
||third.example^$third-party
||all.example^$all
||shout.example^$Important,ALL
||dnstype.example^$dnstype=AAAA
||path.example/ads
||*.wild.example^
||bücher.example^
`

func TestList_IsBlocked(t *testing.T) {
	t.Parallel()

	list, err := FromBytes("test", []byte(testList))
	if err != nil {
		t.Fatalf("from bytes: %v", err)
	}

	testCases := []struct {
		name  string
		qname string
		want  bool
		// wantAllowed is whether an allow rule matches and wins.
		wantAllowed bool
	}{
		{name: "listed", qname: "ads.example.", want: true},
		{name: "below a listed name", qname: "a.b.ads.example.", want: true},
		{name: "allowed below a listed name", qname: "ok.ads.example.", want: false, wantAllowed: true},
		{name: "below an allowed name", qname: "a.ok.ads.example.", want: false, wantAllowed: true},
		{name: "case and no trailing dot", qname: "ADS.Example", want: true},
		{name: "unlisted", qname: "example.", want: false},
		{name: "important over an allow rule", qname: "tracker.example.", want: true},
		{name: "important below an allow rule", qname: "x.tracker.example.", want: true},
		{name: "important allow over important block", qname: "vip.tracker.example.", want: false, wantAllowed: true},
		{name: "option narrowing the rule", qname: "third.example.", want: false},
		{name: "all", qname: "all.example.", want: true},
		{name: "options in any case, combined", qname: "shout.example.", want: true},
		{name: "dns option not understood", qname: "dnstype.example.", want: false},
		{name: "path rule", qname: "path.example.", want: false},
		{name: "wildcard rule", qname: "a.wild.example.", want: false},
		{name: "internationalised name", qname: "xn--bcher-kva.example.", want: true},
		{name: "internationalised name in unicode", qname: "bücher.example.", want: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := list.IsBlocked(testCase.qname); got != testCase.want {
				t.Fatalf("IsBlocked(%q) = %t; want %t", testCase.qname, got, testCase.want)
			}
			if got := list.IsAllowed(testCase.qname); got != testCase.wantAllowed {
				t.Fatalf("IsAllowed(%q) = %t; want %t", testCase.qname, got, testCase.wantAllowed)
			}
		})
	}
}

func TestFromBytes_Header(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		listName    string
		content     string
		wantName    string
		wantVersion string
	}{
		{name: "configured name wins", listName: "configured", content: testList, wantName: "configured", wantVersion: "42"},
		{name: "title", content: testList, wantName: "Test list", wantVersion: "42"},
		{name: "last modified", content: "! Last modified: today\n||a.example^\n", wantVersion: "today"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			list, err := FromBytes(testCase.listName, []byte(testCase.content))
			if err != nil {
				t.Fatalf("from bytes: %v", err)
			}
			if list.Rule.Name != testCase.wantName || list.Rule.Version != testCase.wantVersion {
				t.Fatalf("rule name=%q version=%q; want %q and %q", list.Rule.Name, list.Rule.Version, testCase.wantName, testCase.wantVersion)
			}
		})
	}
}

// A line longer than bufio.Scanner's 64 KiB token limit made the whole list
// fail to parse; at startup the list then installed empty.
func TestFromBytes_OverlongLine(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		line string
	}{
		{name: "overlong rule", line: "||" + strings.Repeat("a", 70_000) + ".example^"},
		{name: "overlong comment", line: "! " + strings.Repeat("x", 200_000)},
		{name: "overlong garbage", line: strings.Repeat("$", 100_000)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			content := "||before.example^\n" + testCase.line + "\n||after.example^\n"
			list, err := FromBytes("test", []byte(content))
			if err != nil {
				t.Fatalf("from bytes: %v", err)
			}
			for _, name := range []string{"before.example.", "after.example."} {
				if !list.IsBlocked(name) {
					t.Fatalf("%s is not blocked; the overlong line took the rest of the list with it", name)
				}
			}
		})
	}
}

// A file larger than the bound is refused, and a reload of one keeps the list
// already loaded. os.ReadFile read a list of any size.
func TestSource_ReloadBoundsSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		maxFileSize int64
		content     string
		wantErr     bool
		wantBlocked string
	}{
		{name: "within the bound", maxFileSize: 1024, content: "||new.example^\n", wantBlocked: "new.example."},
		{name: "over the bound", maxFileSize: 16, content: "||new.example^\n||more.example^\n", wantErr: true, wantBlocked: "old.example."},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "list.txt")
			if err := os.WriteFile(path, []byte("||old.example^\n"), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}
			source := New("test", path)
			if _, err := source.Reload(); err != nil {
				t.Fatalf("first reload: %v", err)
			}

			source.maxFileSize = testCase.maxFileSize
			if err := os.WriteFile(path, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}
			_, err := source.Reload()
			if (err != nil) != testCase.wantErr {
				t.Fatalf("reload error = %v; want an error = %t", err, testCase.wantErr)
			}
			if !source.IsBlocked(testCase.wantBlocked) {
				t.Fatalf("%s is not blocked after the reload", testCase.wantBlocked)
			}
		})
	}
}

func TestSource_NotLoaded(t *testing.T) {
	t.Parallel()

	source := New("test", filepath.Join(t.TempDir(), "absent.txt"))
	if _, err := source.Reload(); err == nil {
		t.Fatal("reload of a missing file succeeded")
	}
	if source.IsBlocked("anything.example.") || source.GetRule() != nil || source.Snapshot() != nil {
		t.Fatal("a source that never loaded blocks something")
	}
}
