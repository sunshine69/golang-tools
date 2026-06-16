package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// Tests: File not found — returns ("", -1, -1, nil, nil)
// ============================================================================

func TestExtractTextBlockContains_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "nonexistent.txt")

	block, startLineNo, endLineNo, datalines, matchedPatterns := ExtractTextBlockContains(
		filePath, nil, nil, nil, 0,
	)

	if block != "" {
		t.Errorf("expected empty block for missing file, got %q", block)
	}
	if startLineNo != -1 || endLineNo != -1 {
		t.Errorf("expected (-1, -1), got (%d, %d)", startLineNo, endLineNo)
	}
	if datalines != nil {
		t.Errorf("expected nil datalines for missing file, got %v", datalines)
	}
	if matchedPatterns != nil {
		t.Errorf("expected nil matchedPatterns for missing file, got %v", matchedPatterns)
	}
}

// ============================================================================
// Tests: searchFrom >= total — returns ("", -1, -1, datalines, matchedPatterns) where datalines is populated
// ============================================================================

func TestExtractTextBlockContains_SearchFromBeyondFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `line1
line2`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, datalines, matchedPatterns := ExtractTextBlockContains(
		filePath, nil, nil, nil, 100, // start_line = 100 (beyond total lines = 2)
	)

	if block != "" {
		t.Errorf("expected empty block for searchFrom >= total, got %q", block)
	}
	if startLineNo != -1 || endLineNo != -1 {
		t.Errorf("expected (-1, -1), got (%d, %d)", startLineNo, endLineNo)
	}
	if datalines == nil || len(datalines) != 2 {
		t.Errorf("expected 2 datalines for searchFrom >= total, got %v", datalines)
	}
	if matchedPatterns == nil {
		t.Errorf("expected non-nil matchedPatterns")
	} else if len(matchedPatterns) != 3 {
		t.Errorf("expected 3 entries in matchedPatterns, got %d", len(matchedPatterns))
	}
}

// ============================================================================
// Tests: No marker — basic extraction with upper and lower bounds
// ============================================================================

func TestExtractTextBlockContains_NoMarker_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `line0
UPPER_BOUND
middle1
middle2
LOWER_BOUND
line5`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, datalines, matchedPatterns := ExtractTextBlockContains(
		filePath,
		[]string{"UPPER_BOUND"}, // upper_bound_pattern - matches index 1
		[]string{"LOWER_BOUND"}, // lower_bound_pattern - matches index 4
		nil,                     // no marker
		0,                       // start_line (from beginning)
	)

	if block != "UPPER_BOUND\nmiddle1\nmiddle2" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 2 { // upperStart = 1 (0-based), so start_line_no = 1+1 = 2
		t.Errorf("expected start_line_no=2, got %d", startLineNo)
	}
	if endLineNo != 4 { // lowerEnd = 4 (0-based index of LOWER_BOUND)
		t.Errorf("expected end_line_no=4, got %d", endLineNo)
	}
	if len(datalines) != 6 {
		t.Errorf("expected 6 datalines, got %d", len(datalines))
	}
	if len(matchedPatterns[0]) != 1 || matchedPatterns[0][0] != "UPPER_BOUND" {
		t.Errorf("unexpected upper bound match: %+v", matchedPatterns[0])
	}
	if len(matchedPatterns[2]) != 1 || matchedPatterns[2][0] != "LOWER_BOUND" {
		t.Errorf("unexpected lower bound match: %+v", matchedPatterns[2])
	}
}

func TestExtractTextBlockContains_NoMarker_BlockIncludesUpperButNotLower(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `UPPER_BOUND
content`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, _ := ExtractTextBlockContains(
		filePath,
		nil, // empty upper - use searchFrom (0-based index 0)
		nil, // empty lower - use total lines (2), so blockLines = datalines[0:2] = all lines joined
		nil,
		0,
	)

	if block != "UPPER_BOUND\ncontent" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 { // upperStart = searchFrom = 0 (0-based), so start_line_no = 0+1 = 1
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 2 { // total lines = 2
		t.Errorf("expected end_line_no=2, got %d", endLineNo)
	}
}

func TestExtractTextBlockContains_NoMarker_RegexPattern(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `=== SECTION START ===
content1
content2
=== SECTION END ===`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, _ := ExtractTextBlockContains(
		filePath,
		[]string{`=== SECTION START ===`}, // exact match via regex
		[]string{`=== SECTION END ===`},   // exact match via regex
		nil,
		0,
	)

	if block != "=== SECTION START ===\ncontent1\ncontent2" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 { // upperStart = 0 (0-based), so start_line_no = 0+1 = 1
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 4 { // lowerEnd = 3 (0-based index of "=== SECTION END ===")
		t.Errorf("expected end_line_no=4, got %d", endLineNo)
	}
}

func TestExtractTextBlockContains_NoMarker_CapturingRegex(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `--- START ---
content1
content2
--- END ---`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, matchedPatterns := ExtractTextBlockContains(
		filePath,
		[]string{`--- (.+) ---`}, // captures "START" into group 1
		[]string{`--- (.+) ---`}, // captures "END" into group 1
		nil,
		0,
	)

	if block != "--- START ---\ncontent1\ncontent2" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 {
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 4 { // lowerEnd = 3 (0-based index of "--- END ---")
		t.Errorf("expected end_line_no=4, got %d", endLineNo)
	}
	// matchedPatterns[0] contains the pattern string that matched, NOT capture groups
	if len(matchedPatterns[0]) != 1 || matchedPatterns[0][0] != "--- (.+) ---" {
		t.Errorf("unexpected upper bound match: %+v", matchedPatterns[0])
	}
	if len(matchedPatterns[2]) != 1 || matchedPatterns[2][0] != "--- (.+) ---" {
		t.Errorf("unexpected lower bound match: %+v", matchedPatterns[2])
	}
}

func TestExtractTextBlockContains_NoMarker_MultipleUpperMatches(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `UPPER_A
content1
UPPER_B
LOWER_C`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, _ := ExtractTextBlockContains(
		filePath,
		[]string{"UPPER"}, // partial match - matches both UPPER_A and UPPER_B
		[]string{"LOWER_C"},
		nil,
		0,
	)

	if block != "UPPER_A\ncontent1" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 { // first match of upper_bound_pattern (index 0), so start_line_no = 0+1 = 1
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 4 { // lowerEnd = 3 (0-based index of LOWER_C)
		t.Errorf("expected end_line_no=4, got %d", endLineNo)
	}
}

func TestExtractTextBlockContains_NoMarker_MultipleLowerMatches(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `UPPER_A
content1
LOWER_B
LOWER_C`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, _ := ExtractTextBlockContains(
		filePath,
		[]string{"UPPER_A"},
		[]string{"LOWER_."}, // partial match - matches both LOWER_B and LOWER_C (regex pattern with .)
		nil,
		0,
	)

	if block != "UPPER_A\ncontent1" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 { // upperStart = 0 (0-based), so start_line_no = 0+1 = 1
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 3 { // first match of lower_bound_pattern is LOWER_B at index 2, so lowerEnd = 2
		t.Errorf("expected end_line_no=3, got %d", endLineNo)
	}
}

func TestExtractTextBlockContains_NoMarker_InvalidRegexSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `UPPER_BOUND
content1
LOWER_BOUND`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, _, _ := ExtractTextBlockContains(
		filePath,
		nil, // empty upper - use searchFrom (0-based index 0)
		[]string{`[invalid regex`, `LOWER_BOUND`}, // first pattern is invalid — should be skipped by matchAny
		nil,
		0,
	)

	if block != "UPPER_BOUND\ncontent1" {
		t.Errorf("unexpected block: got %q", block)
	}
	if startLineNo != 1 {
		t.Errorf("expected start_line_no=1, got %d", startLineNo)
	}
	if endLineNo != 3 { // lowerEnd = 2 (0-based index of LOWER_BOUND)
		t.Errorf("expected end_line_no=3, got %d", endLineNo)
	}
}

func TestExtractTextBlockContains_NoMarker_NoUpperMatch(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `line0
UPPER_BOUND
content1`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, datalines, _ := ExtractTextBlockContains(
		filePath,
		nil, // empty upper - use searchFrom (0-based index 0)
		nil, // empty lower - use total lines (3), so blockLines = datalines[0:3] = all lines joined
		nil,
		100, // start_line beyond file — returns early with ("", -1, -1, datalines, matchedPatterns)
	)

	if block != "" {
		t.Errorf("expected empty block for searchFrom >= total, got %q", block)
	}
	if startLineNo != -1 || endLineNo != -1 {
		t.Errorf("expected (-1, -1), got (%d, %d)", startLineNo, endLineNo)
	}
	if datalines == nil || len(datalines) != 3 {
		t.Errorf("expected 3 datalines for searchFrom >= total, got %v", datalines)
	}
}

func TestExtractTextBlockContains_NoMarker_NoLowerMatch(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	content := `UPPER_BOUND
content1`

	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	block, startLineNo, endLineNo, datalines, _ := ExtractTextBlockContains(
		filePath,
		nil, // empty upper - use searchFrom (0-based index 0)
		nil, // empty lower - use total lines (2), so blockLines = datalines[0:2] = all lines joined
		nil,
		100, // start_line beyond file — returns early with ("", -1, -1, datalines, matchedPatterns)
	)

	if block != "" {
		t.Errorf("expected empty block for searchFrom >= total, got %q", block)
	}
	if startLineNo != -1 || endLineNo != -1 {
		t.Errorf("expected (-1, -1), got (%d, %d)", startLineNo, endLineNo)
	}
	if datalines == nil || len(datalines) != 2 {
		t.Errorf("expected 2 datalines for searchFrom >= total, got %v", datalines)
	}
}
