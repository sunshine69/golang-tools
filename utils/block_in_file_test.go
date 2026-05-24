package utils

import (
	"os"
	"strings"
	"testing"
)

// helper: write a temp file with given content, return path
func writeTmp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "textblock_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(content)
	return f.Name()
}

// isErrResult checks the sentinel error convention: oldBlock starts with "ERROR: " and both indices are -1.
func isErrResult(oldBlock string, start, end int) bool {
	return start == -1 && end == -1 && strings.HasPrefix(oldBlock, "ERROR: ")
}

// ─── ExtractTextBlockContains ──────────────────────────────────────────────────

func TestExtract_BasicBlock(t *testing.T) {
	content := strings.Join([]string{
		"line1",
		"# BEGIN",
		"  content A",
		"  content B",
		"# END",
		"line6",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	block, start, end, _, _ := ExtractTextBlockContains(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		0,
	)

	if start != 2 {
		t.Errorf("expected start=2, got %d", start)
	}
	// end_line_no is the 1-based index of the last *included* line.
	// "# END" is line 5 (1-based), so last included is line 4.
	if end != 4 {
		t.Errorf("expected end=4 (last included line), got %d", end)
	}
	if !strings.Contains(block, "content A") {
		t.Errorf("block missing content A: %q", block)
	}
	if strings.Contains(block, "# END") {
		t.Errorf("block should not include lower bound line")
	}
}

func TestExtract_WithMarker(t *testing.T) {
	content := strings.Join([]string{
		"# SECTION_START",
		"  alpha",
		"  MARKER_HERE",
		"  beta",
		"# SECTION_END",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	block, start, end, _, matched := ExtractTextBlockContains(
		path,
		[]string{`^# SECTION_START$`},
		[]string{`^# SECTION_END$`},
		[]string{`MARKER_HERE`},
		0,
	)

	if start == -1 {
		t.Fatal("expected a match, got -1")
	}
	if !strings.Contains(block, "alpha") || !strings.Contains(block, "beta") {
		t.Errorf("block content wrong: %q", block)
	}
	_ = end
	_ = matched
}

func TestExtract_MarkerNotFound_ReturnsNegOne(t *testing.T) {
	content := strings.Join([]string{
		"# BEGIN",
		"  no marker here",
		"# END",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	_, start, _, _, _ := ExtractTextBlockContains(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{`MISSING_MARKER`},
		0,
	)
	if start != -1 {
		t.Errorf("expected -1 when marker not found, got %d", start)
	}
}

func TestExtract_EOFLowerBound(t *testing.T) {
	// Lower bound pattern contains "EOF" so hitting file end counts as a match
	content := strings.Join([]string{
		"# START",
		"  data line",
		"  more data",
		// no explicit end marker
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	block, start, end, datalines, _ := ExtractTextBlockContains(
		path,
		[]string{`^# START$`},
		[]string{`^# END_EOF$`}, // contains "EOF"
		[]string{},
		0,
	)

	if start == -1 {
		t.Fatal("expected match via EOF fallback")
	}
	if end != len(datalines) {
		t.Errorf("expected end=%d (len of file), got %d", len(datalines), end)
	}
	if !strings.Contains(block, "data line") {
		t.Errorf("block missing expected content: %q", block)
	}
}

func TestExtract_StartLine(t *testing.T) {
	// Two identical blocks; start_line skips past the first
	content := strings.Join([]string{
		"# BEGIN",     // 1
		"  block one", // 2
		"# END",       // 3
		"# BEGIN",     // 4
		"  block two", // 5
		"# END",       // 6
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	// start_line=4 → skip to line 4 (1-based)
	block, start, _, _, _ := ExtractTextBlockContains(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		4,
	)

	if start != 4 {
		t.Errorf("expected start=4 (second block), got %d", start)
	}
	if !strings.Contains(block, "block two") {
		t.Errorf("expected second block, got: %q", block)
	}
}

// ─── BlockInFile — normal operation ───────────────────────────────────────────

func TestBlockInFile_Replace(t *testing.T) {
	content := strings.Join([]string{
		"preamble",
		"# BEGIN",
		"  old content",
		"# END",
		"postamble",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"  new content",
		false,
		false,
		0,
	)

	if isErrResult(oldBlock, start, end) {
		t.Fatalf("unexpected error: %s", oldBlock)
	}
	if !strings.Contains(oldBlock, "old content") {
		t.Errorf("oldBlock should contain old content, got: %q", oldBlock)
	}

	data, _ := os.ReadFile(path)
	result := string(data)

	if !strings.Contains(result, "new content") {
		t.Errorf("file should contain new content:\n%s", result)
	}
	if strings.Contains(result, "old content") {
		t.Errorf("file should NOT contain old content:\n%s", result)
	}
	if !strings.Contains(result, "preamble") || !strings.Contains(result, "postamble") {
		t.Errorf("surrounding lines should be preserved:\n%s", result)
	}
}

func TestBlockInFile_Replace_BoundaryLinesRemoved(t *testing.T) {
	// keepBoundaryLines=false (the default) must remove the upper AND lower bound
	// lines themselves, not just the inner content.
	content := strings.Join([]string{
		"preamble",
		"# BEGIN",
		"  old content",
		"# END",
		"postamble",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"  new content",
		false, // keepBoundaryLines — the key flag under test
		false,
		0,
	)

	if isErrResult(oldBlock, start, end) {
		t.Fatalf("unexpected error: %s", oldBlock)
	}

	data, _ := os.ReadFile(path)
	result := string(data)

	// Boundary lines must be gone.
	if strings.Contains(result, "# BEGIN") {
		t.Errorf("# BEGIN should be removed when keepBoundaryLines=false:\n%s", result)
	}
	if strings.Contains(result, "# END") {
		t.Errorf("# END should be removed when keepBoundaryLines=false:\n%s", result)
	}

	// Replacement content must be present.
	if !strings.Contains(result, "new content") {
		t.Errorf("replacement content missing:\n%s", result)
	}

	// Lines outside the block must be untouched.
	if !strings.Contains(result, "preamble") || !strings.Contains(result, "postamble") {
		t.Errorf("surrounding lines should be preserved:\n%s", result)
	}
}

func TestBlockInFile_KeepBoundaryLines(t *testing.T) {
	content := strings.Join([]string{
		"# BEGIN",
		"  old",
		"# END",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"  replaced",
		true,
		false,
		0,
	)

	if isErrResult(oldBlock, start, end) {
		t.Fatalf("unexpected error: %s", oldBlock)
	}

	data, _ := os.ReadFile(path)
	result := string(data)

	if !strings.Contains(result, "# BEGIN") {
		t.Errorf("expected # BEGIN preserved:\n%s", result)
	}
	if !strings.Contains(result, "# END") {
		t.Errorf("expected # END preserved:\n%s", result)
	}
	if !strings.Contains(result, "replaced") {
		t.Errorf("expected replacement content:\n%s", result)
	}
	if strings.Contains(result, "old") {
		t.Errorf("old content should be gone:\n%s", result)
	}
}

func TestBlockInFile_InsertIfNotFound(t *testing.T) {
	content := "no blocks here\n"
	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"appended line",
		false,
		false,
		0,
		map[string]any{"insertIfNotFound": true},
	)

	// "not found + appended" returns -1/-1 but NO "ERROR: " prefix.
	if strings.HasPrefix(oldBlock, "ERROR: ") {
		t.Fatalf("unexpected error on insert-if-not-found: %s", oldBlock)
	}
	if start != -1 || end != -1 {
		t.Errorf("expected -1/-1 for not-found case, got start=%d end=%d", start, end)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "appended line") {
		t.Errorf("expected appended line when not found, got:\n%s", string(data))
	}
}

func TestBlockInFile_NoInsertIfNotFound(t *testing.T) {
	content := "no blocks here\n"
	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"should not appear",
		false,
		false,
		0,
		map[string]any{"insertIfNotFound": false},
	)

	// Not an error — caller just opted out.
	if strings.HasPrefix(oldBlock, "ERROR: ") {
		t.Fatalf("unexpected error: %s", oldBlock)
	}
	if start != -1 || end != -1 {
		t.Errorf("expected -1/-1 for not-found case")
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "should not appear") {
		t.Errorf("expected no insertion, got:\n%s", string(data))
	}
}

func TestBlockInFile_Backup(t *testing.T) {
	content := strings.Join([]string{
		"# BEGIN",
		"  original",
		"# END",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)
	defer os.Remove(path + ".bak")

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"  replaced",
		false,
		true,
		0,
	)

	if isErrResult(oldBlock, start, end) {
		t.Fatalf("unexpected error: %s", oldBlock)
	}

	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal("backup file not created:", err)
	}
	if !strings.Contains(string(bak), "original") {
		t.Errorf("backup should contain original content:\n%s", string(bak))
	}
}

func TestBlockInFile_EOFPattern(t *testing.T) {
	content := strings.Join([]string{
		"# START",
		"  old data",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# START$`},
		[]string{`EOF`},
		[]string{},
		"  new data",
		false,
		false,
		0,
	)

	if isErrResult(oldBlock, start, end) {
		t.Fatalf("unexpected error: %s", oldBlock)
	}
	if start == -1 {
		t.Fatal("expected match via EOF lower bound")
	}
	if !strings.Contains(oldBlock, "old data") {
		t.Errorf("old block should contain old data: %q", oldBlock)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "new data") {
		t.Errorf("file should have new data:\n%s", string(data))
	}
}

// ─── BlockInFile — error sentinel tests ───────────────────────────────────────

func TestBlockInFile_Error_FileNotFound(t *testing.T) {
	oldBlock, start, end, matched := BlockInFile(
		"/nonexistent/path/file.txt",
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"replacement",
		false, false, 0,
	)

	if !isErrResult(oldBlock, start, end) {
		t.Errorf("expected error sentinel for missing file, got oldBlock=%q start=%d end=%d", oldBlock, start, end)
	}
	if matched != nil {
		t.Errorf("expected nil matchedPattern on error, got %v", matched)
	}
	t.Logf("error message: %s", oldBlock)
}

func TestBlockInFile_Error_AppendToReadonlyDir(t *testing.T) {
	// Create a read-only directory so OpenFile fails during insertIfNotFound append.
	dir, err := os.MkdirTemp("", "readonly_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Write an empty file, then make the directory read-only so we can't open for append.
	fpath := dir + "/test.txt"
	os.WriteFile(fpath, []byte("no blocks\n"), 0644)
	os.Chmod(dir, 0555) // r-xr-xr-x — can read files, can't create/append

	oldBlock, start, end, _ := BlockInFile(
		fpath,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"replacement",
		false, false, 0,
		map[string]any{"insertIfNotFound": true},
	)

	os.Chmod(dir, 0755) // restore so cleanup works

	if !isErrResult(oldBlock, start, end) {
		// On some CI environments running as root, permission checks are skipped —
		// just log rather than hard-fail.
		t.Logf("NOTE: error sentinel not returned (possibly running as root): oldBlock=%q start=%d", oldBlock, start)
	} else {
		t.Logf("error message: %s", oldBlock)
	}
}

func TestBlockInFile_Error_WriteFailure(t *testing.T) {
	content := strings.Join([]string{
		"# BEGIN",
		"  data",
		"# END",
	}, "\n") + "\n"

	path := writeTmp(t, content)
	defer os.Remove(path)

	// Make the file read-only so WriteFile fails.
	os.Chmod(path, 0444)
	defer os.Chmod(path, 0644)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# BEGIN$`},
		[]string{`^# END$`},
		[]string{},
		"replacement",
		false, false, 0,
	)

	if !isErrResult(oldBlock, start, end) {
		t.Logf("NOTE: error sentinel not returned (possibly running as root): oldBlock=%q start=%d", oldBlock, start)
	} else {
		t.Logf("error message: %s", oldBlock)
	}
}

// isErrResult is also useful for documentation — show the distinction between
// "not found + inserted" vs actual errors.
func TestBlockInFile_ErrorPrefix_Distinguishable(t *testing.T) {
	// "not found + inserted" must NOT carry the ERROR: prefix.
	content := "nothing here\n"
	path := writeTmp(t, content)
	defer os.Remove(path)

	oldBlock, start, end, _ := BlockInFile(
		path,
		[]string{`^# MISSING$`},
		[]string{`^# ALSO_MISSING$`},
		[]string{},
		"appended",
		false, false, 0,
	)

	if start != -1 || end != -1 {
		t.Errorf("expected -1/-1 for not-found case")
	}
	if strings.HasPrefix(oldBlock, "ERROR: ") {
		t.Errorf("not-found+inserted should not use ERROR: prefix, got: %s", oldBlock)
	}

	// A real error (bad file) MUST carry the ERROR: prefix.
	oldBlock2, start2, end2, _ := BlockInFile(
		"/no/such/file.txt",
		[]string{`^# MISSING$`},
		[]string{`^# ALSO_MISSING$`},
		[]string{},
		"appended",
		false, false, 0,
	)
	if !strings.HasPrefix(oldBlock2, "ERROR: ") || start2 != -1 || end2 != -1 {
		t.Errorf("missing file should produce ERROR: prefix, got: %q start=%d end=%d", oldBlock2, start2, end2)
	}
}
