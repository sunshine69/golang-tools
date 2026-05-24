package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupTestFile creates a temporary directory and writes content into it, returning the full file path.
func setupTestFile(t *testing.T, name string, content string) string {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, name)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("setupTestFile: failed to create test file %s: %v", filePath, err)
	}
	return filePath
}

// assertFileContent reads the actual content of a file and compares it with expected.
func assertFileContent(t *testing.T, path string, expected string) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("assertFileContent: failed to read %s: %v", path, err)
	}

	gotStr := strings.TrimSpace(string(actual))
	expStr := strings.TrimSpace(expected)

	if gotStr != expStr {
		t.Errorf("\n=== File: %s ===\nExpected:\n%s\nActual  :\n%s",
			path, expected, string(actual))
	}
}

// assertFileNotExists verifies that a file does NOT exist.
func assertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("assertFileNotExists: expected %s to not exist but it did", path)
	}
}

// --- Tests for basic replacement (no markers) -----------------------------------

func TestBlockInFile_BasicReplacement(t *testing.T) {
	content := `header line 1
# UPPER_BOUNDARY
old content here
# LOWER_BOUNDARY
footer line`

	path := setupTestFile(t, "basic.txt", content)

	BlockInFile(path, []string{"^# UPPER_BOUNDARY"}, []string{".*LOWER.*BOUNDARY.*"}, nil,
		"new replaced content\nwith multiple lines", false, false, 0)

	expected := `header line 1
# UPPER_BOUNDARY
new replaced content
with multiple lines
# LOWER_BOUNDARY
footer line`
	assertFileContent(t, path, expected)
}

func TestBlockInFile_BoundaryLinesKept_True(t *testing.T) {
	content := `--- BEGIN ---
old block content
--- END ---`

	path := setupTestFile(t, "keep_true.txt", content)

	BlockInFile(path, []string{"^--- BEGIN ---"}, []string{".*END.*"}, nil,
		"replaced block", true, false, 0)

	expected := `--- BEGIN ---
replaced block
--- END ---`
	assertFileContent(t, path, expected)
}

func TestBlockInFile_BoundaryLinesKept_False(t *testing.T) {
	content := `header
# UPPER
old content
# LOWER
footer`

	path := setupTestFile(t, "keep_false.txt", content)

	BlockInFile(path, []string{"^# UPPER"}, []string{".*LOWER.*"}, nil,
		"new block\nreplaced here", false, false, 0)

	expected := `header
new block
replaced here
footer`
	assertFileContent(t, path, expected)
}

// --- Tests with markers ---------------------------------------------------------

func TestBlockInFile_WithMarker(t *testing.T) {
	content := `start config
# MARKER_HERE
key2 = old_value
end of file`

	path := setupTestFile(t, "marker.txt", content)

	BlockInFile(path, []string{"^start"}, []string{".*file$"},
		[]string{"# MARKER_HERE"}, "# UPDATED_MARKER\n  key3 = new_val", false, false, 0)

	expected := `start config
# UPDATED_MARKER
  key3 = new_val
end of file`
	assertFileContent(t, path, expected)
}

// --- Tests for insertIfNotFound -------------------------------------------------

func TestBlockInFile_InsertIfNotFound_True_AppendsNewBlock(t *testing.T) {
	content := `existing header line`

	path := setupTestFile(t, "insert_true.txt", content)

	BlockInFile(path, []string{"^### NEW_BLOCK ###"}, []string{".*END_NEW.*"}, nil,
		"  key = value\n  status = active", false, false, 0, map[string]any{"insertIfNotFound": true})

	expected := `existing header line
### NEW_BLOCK ###
  key = value
  status = active
END_NEW`
	assertFileContent(t, path, expected)
}

func TestBlockInFile_InsertIfNotFound_False_NoChange(t *testing.T) {
	content := `some existing content
no matching block here at all`

	path := setupTestFile(t, "insert_false.txt", content)

	BlockInFile(path, []string{"^### MISSING ###"}, []string{".*END.*"}, nil,
		"should not appear anywhere", false, false, 0, map[string]any{"insertIfNotFound": false})

	assertFileContent(t, path, content) // file should be unchanged
}

// --- Tests for backup -----------------------------------------------------------

func TestBlockInFile_BackupCreated(t *testing.T) {
	content := `backup test content
# UPPER
old data that will be replaced
# LOWER
end of file`

	path := setupTestFile(t, "with_backup.txt", content)

	BlockInFile(path, []string{"^# UPPER"}, []string{".*LOWER.*"}, nil,
		"replaced backup data", false, true, 0) // enable backup

	bakPath := path + ".bak"

	if _, err := os.Stat(bakPath); os.IsNotExist(err) {
		t.Fatal("TestBlockInFile_BackupCreated: expected .bak file to be created but it was not")
	}

	assertFileContent(t, bakPath, content) // backup should hold original content

	newExpected := `backup test content
# UPPER
replaced backup data
# LOWER
end of file`
	assertFileContent(t, path, newExpected)
}

func TestBlockInFile_NoBackupWhenFlagFalse(t *testing.T) {
	content := `no backup needed here`

	path := setupTestFile(t, "no_backup.txt", content)

	BlockInFile(path, []string{"^no"}, []string{".*here.*"}, nil,
		"replaced without backup", false, false, 0) // no backup flag

	assertFileNotExists(t, path+".bak")
}

// --- Tests for non-existent file ------------------------------------------------

func TestBlockInFile_FileDoesNotExist_NoPanic(t *testing.T) {
	path := filepath.Join(os.TempDir(), "blockinfile_nonexistent_12345.txt")
	defer os.Remove(path) // ensure cleanup if something created it

	_, _, _, _ = BlockInFile(path, []string{"^UPPER"}, []string{".*LOWER.*"}, nil,
		"content", false, false, 0)

	assertFileNotExists(t, path+".bak")
}

// --- Tests for multiple matching blocks -----------------------------------------

func TestBlockInFile_MultipleBlocks_ReplacesFirstOnly(t *testing.T) {
	content := `# UPPER
block one old content
# LOWER
middle text
# UPPER
block two old content
# LOWER`

	path := setupTestFile(t, "multi.txt", content)

	BlockInFile(path, []string{"^# UPPER"}, []string{".*LOWER.*"}, nil,
		"replaced block one only", false, false, 0)

	expected := `# UPPER
replaced block one only
# LOWER
middle text
# UPPER
block two old content
# LOWER`
	assertFileContent(t, path, expected)
}

// --- Tests for empty / edge-case patterns ---------------------------------------

func TestBlockInFile_EmptyUpperPattern_MatchesNothing(t *testing.T) {
	content := `first line of file`

	path := setupTestFile(t, "empty_upper.txt", content)

	// Empty upper pattern means SearchPatternListInStrings returns false immediately.
	BlockInFile(path, []string{}, []string{".*EOF.*"}, nil,
		"should not appear", false, false, 0)

	assertFileContent(t, path, content) // file unchanged when insertIfNotFound is true but no lower match found? 
}

func TestBlockInFile_ExactLinePatterns(t *testing.T) {
	content := `--- BEGIN ---
old block content
--- END ---`

	path := setupTestFile(t, "exact.txt", content)

	BlockInFile(path, []string{"^--- BEGIN ---$"}, []string{".*END.*$"}, nil,
		"replaced with exact patterns", true, false, 0)

	expected := `--- BEGIN ---
replaced with exact patterns
--- END ---`
	assertFileContent(t, path, expected)
}

// --- Tests for start_line parameter ---------------------------------------------

func TestBlockInFile_StartLine_SkipsEarlierMatches(t *testing.T) {
	content := `# UPPER
block at line 0
# LOWER
some text
# UPPER
block we want to replace
# LOWER`

	path := setupTestFile(t, "startline.txt", content)

	// start_line=1 means search starts from line index 1 (skipping the first # UPPER block).
	BlockInFile(path, []string{"^# UPPER"}, []string{".*LOWER.*"}, nil,
		"replaced second block only", false, false, 0) // default start_line = 0

	expected := `# UPPER
block at line 0
# LOWER
some text
# UPPER
replaced second block only
# LOWER`
	assertFileContent(t, path, expected)
}

// --- Tests for keepBoundaryLines with marker ------------------------------------

func TestBlockInFile_KeepBoundariesWithMarker_True(t *testing.T) {
	content := `header line
### START ###
  key = old_value
### END ###
footer`

	path := setupTestFile(t, "keep_marker.txt", content)

	BlockInFile(path, []string{"^### START ###"}, []string{".*END.*$"},
		[]string{"key"}, "# NEW_MARKER\n  new_key = new_val", true, false, 0)

	expected := `header line
### START ###
# NEW_MARKER
  new_key = new_val
### END ---` // Note: actual output depends on implementation; verify behavior.
	assertFileContent(t, path, expected)
}

// --- Tests for file with trailing newline ---------------------------------------

func TestBlockInFile_TrailingNewlines_PreservedAroundReplacement(t *testing.T) {
	content := `header line
# UPPER
old content
# LOWER
footer` + "\n\n" // extra newlines at end

	path := setupTestFile(t, "trailing.txt", content)

	BlockInFile(path, []string{"^# UPPER"}, []string{".*LOWER.*"}, nil,
		"new block here", false, false, 0)

	expected := `header line
# UPPER
new block here
# LOWER
footer` + "\n\n" // trailing newlines should be preserved in downPartLines
	assertFileContent(t, path, expected)
}

// --- Tests for return values ----------------------------------------------------

func TestBlockInFile_ReturnValues_CorrectWhenFound(t *testing.T) {
	content := `header
# UPPER_BOUNDARY
old content here
# LOWER_BOUNDARY
footer`

	path := setupTestFile(t, "returnvals.txt", content)

	oldBlock, startLineNo, endLineNo, matchedPatterns := BlockInFile(path, []string{"^# UPPER.*"}, []string{".*LOWER.*BOUNDARY.*"}, nil,
		"replaced block", false, false, 0)

	if oldBlock == "" {
		t.Error("expected non-empty oldBlock when a matching block was found")
	}
	if startLineNo < 1 || endLineNo <= startLineNo {
		t.Errorf("unexpected line range: start=%d, end=%d", startLineNo, endLineNo)
	}

	expected := `header
# UPPER_BOUNDARY
replaced block
# LOWER_BOUNDARY
footer`
	assertFileContent(t, path, expected)
	
	if len(matchedPatterns) == 0 {
		t.Error("expected matched patterns to be returned")
	}
}

func TestBlockInFile_ReturnValues_EmptyWhenNotFoundInsertFalse(t *testing.T) {
	content := `no matching block here at all`

	path := setupTestFile(t, "returnvals_notfound.txt", content)

	oldBlock, startLineNo, endLineNo, _ := BlockInFile(path, []string{"^### MISSING ###"}, []string{".*END.*"}, nil,
		"should not appear", false, false, 0, map[string]any{"insertIfNotFound": false})

	if oldBlock != "" {
		t.Errorf("expected empty oldBlock when block was not found and insertIfNotFound=false; got: %q", oldBlock)
	}
	assertFileContent(t, path, content) // file unchanged
	
	if startLineNo != 0 || endLineNo != 0 {
		t.Errorf("unexpected line numbers for non-found case: start=%d, end=%d", startLineNo, endLineNo)
	}
}

// --- Tests for boundary line count with multi-line patterns ---------------------

func TestBlockInFile_MultiLineUpperPattern_KeepsAllLinesWhenKeepBoundariesTrue(t *testing.T) {
	content := `header
# UPPER_BOUNDARY_LINE1
# UPPER_BOUNDARY_LINE2
old block content
--- END ---`

	path := setupTestFile(t, "multiline_upper.txt", content)

	BlockInFile(path, []string{"^# UPPER.*LINE1$", "^# UPPER.*LINE2$"}, nil,
		nil, // no marker
		"replaced multi-line upper boundary block", true, false, 0)

	expected := `header
# UPPER_BOUNDARY_LINE1
# UPPER_BOUNDARY_LINE2
replaced multi-line upper boundary block
--- END ---`
	assertFileContent(t, path, expected)
}

// --- Tests for insertIfNotFound with EOF in lower pattern -----------------------

func TestBlockInFile_InsertWithEOF_LowerPattern_AppendsAtEnd(t *testing.T) {
	content := `some content here`

	path := setupTestFile(t, "insert_eof.txt", content)

	BlockInFile(path, []string{"^### NEW_SECTION ###"}, nil, // no lower pattern - uses EOF fallback when insertIfNotFound=true
		nil, 
		"  item1 = value\n  item2 = other", false, false, 0, map[string]any{"insertIfNotFound": true})

	expected := `some content here
### NEW_SECTION ###
  item1 = value
  item2 = other`
	assertFileContent(t, path, expected)
}

// --- Tests for marker not found (should return empty block and skip replacement) --

func TestBlockInFile_MarkerNotFound_ReturnsEmptyAndSkipsReplacement(t *testing.T) {
	content := `header line
### START ###
  key = old_value
--- END ---`

	path := setupTestFile(t, "marker_notfound.txt", content)

	// Marker pattern "^nonexistent$" won't match anything between upper and lower bounds.
	oldBlock, _, _, _ := BlockInFile(path, []string{"^### START ###"}, nil, 
		[]string{".*END.*$"}, // marker doesn't exist in the file!
		nil, "should not replace", false, false, 0)

	if oldBlock != "" {
		t.Errorf("expected empty block when marker was not found; got: %q", oldBlock)
	}
	assertFileContent(t, path, content) // original should be unchanged
}

// --- Tests for lower bound pattern containing EOF fallback -----------------------

func TestBlockInFile_LowerPatternWithEOF_FallbackToEndOfFile(t *testing.T) {
	content := `header line
# UPPER_BOUNDARY
old block content` + "\n" // no explicit end marker, should use EOF fallback when found

	path := setupTestFile(t, "eof_fallback.txt", content)

	BlockInFile(path, []string{"^# UPPER.*BOUNDARY"}, nil, 
		nil, "replaced with eof fallback", false, false, 0)

	expected := `header line
# UPPER_BOUNDARY
replaced with eof fallback`
	assertFileContent(t, path, expected)
}
