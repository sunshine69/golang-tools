package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Grep a pattern in a text
func Grep[T string | *regexp.Regexp](input string, pattern T, outputMatchOnly bool, inverse bool) (out []string, matchedFound bool) {
	var re *regexp.Regexp
	switch v := any(pattern).(type) {
	case string:
		re = regexp.MustCompile(v)
	case *regexp.Regexp:
		re = v
	}
	lines := strings.Split(input, "\n")
	oputputlines := []string{}
	for _, line := range lines {
		matched := re.MatchString(line)
		// -v : inverse match (print non-matching lines)
		if inverse {
			if !matched {
				oputputlines = append(oputputlines, line)
				matchedFound = true
			}
			continue
		}
		// Normal grep behavior
		if !matched {
			continue
		}
		matchedFound = true
		if outputMatchOnly {
			// Print matches (or capture groups)
			matches := re.FindStringSubmatch(line)
			// println(JsonDump(matches, ""))
			if len(matches) > 1 {
				oputputlines = append(oputputlines, strings.Join(matches[1:], " "))
			} else {
				oputputlines = append(oputputlines, line)
			}

		} else {
			// Print whole line OR capture(s)
			m := re.FindStringSubmatch(line)
			if len(m) > 0 {
				oputputlines = append(oputputlines, line)
			}
		}
	}
	return oputputlines, matchedFound
}

// Grep a pattern in a stream of text. Just print meatches oout as they go. Suitable for large file or stdin
// If input size > 1MB use this.
// If replace is not empty then it does the replacement by line. Capture in the form $N will be replaced as well.
func GrepStream[T string | *regexp.Regexp](input io.ReadCloser, pattern T, outputMatchOnly bool, inverse bool, outputPrefix, replace string) (matchedFound bool) {
	defer input.Close()

	var re *regexp.Regexp
	switch v := any(pattern).(type) {
	case string:
		re = regexp.MustCompile(v)
	case *regexp.Regexp:
		re = v
	}
	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		line := scanner.Text()
		matched := re.MatchString(line)
		// -v : inverse match (print non-matching lines)
		if inverse {
			if !matched {
				fmt.Fprintln(os.Stdout, outputPrefix+line)
				matchedFound = true
			}
			continue
		}
		// Normal grep behavior
		if !matched {
			if replace != "" { // replace mode, not match we print out as is
				fmt.Fprintln(os.Stdout, line)
			}
			continue
		}
		matchedFound = true
		if replace != "" {
			fmt.Fprintln(os.Stdout, SearchReplaceString(line, re, replace, -1))
			continue
		}
		matches := re.FindStringSubmatch(line)
		if outputMatchOnly {
			// Print matches (or capture groups)
			// println(JsonDump(matches, ""))
			if len(matches) > 1 {
				fmt.Fprintln(os.Stdout, outputPrefix+strings.Join(matches[1:], " "))
			} else {
				fmt.Fprintln(os.Stdout, outputPrefix+line)
			}
		} else {
			// Print whole line OR capture(s)
			if len(matches) > 0 {
				fmt.Fprintln(os.Stdout, outputPrefix+line)
			}
		}
	}
	// Check for any errors that occurred during scanning.
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner error: %s", err.Error())
	}
	return
}

// Grep files in a dir. Used it when you know files are small enough like less than 100MB.
// For large file to grep you have to use the GrepStream function
func FileGrep(filePaths, patternStr, excludePtnStr string, outputMatchOnly, inverse bool) (foundMatch bool) {
	var excludePtn *regexp.Regexp
	var maxSize int64 = 100000000 // 100MB - only read max to that to grep
	if excludePtnStr != "" {
		excludePtn = regexp.MustCompile(excludePtnStr)
	}
	pattern := regexp.MustCompile(patternStr)

	err := filepath.Walk(filePaths, func(fpath string, info fs.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
		fname := info.Name()
		if info.IsDir() && (excludePtn != nil && excludePtn.MatchString(fname)) {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			fmode := info.Mode()
			if !(fmode.IsRegular()) {
				return nil
			}
			if test, err := IsBinaryFileSimple(fpath); test {
				if err != nil {
					fmt.Fprintf(os.Stderr, "[ERROR] IsBinaryFileSimple %s\n", err.Error())
				}
				return filepath.SkipDir
			}

			file, err := os.Open(fpath)
			if err != nil {
				return nil
			}
			defer file.Close()
			var textb []byte
			if info.Size() < maxSize {
				textb, err = os.ReadFile(fpath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[ERROR] readfile - %s\n", err.Error())
					return nil
				}
			} else {
				textb = make([]byte, maxSize)
				// ReadFull fills the buffer completely or returns an error
				_, err := io.ReadFull(file, textb)
				if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
					return nil
				}
			}

			matchedLines, found := Grep(string(textb), pattern, outputMatchOnly, inverse)
			if found {
				foundMatch = true
				if !outputMatchOnly {
					for _, l := range matchedLines {
						fmt.Fprintf(os.Stdout, "%s:%s\n", fpath, l)
					}
				} else {
					for _, l := range matchedLines {
						fmt.Fprintf(os.Stdout, "%s\n", l)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", err.Error())
		return false
	}
	return
}

// ChunkString - Break a strings into a chunk of size chunkSize
func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}
	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// ReplaceAllFuncN extends regexp.Regexp to support count of replacements for []byte
func ReplaceAllFuncN(re *regexp.Regexp, src []byte, repl func([]int, [][]byte) []byte, n int) ([]byte, int) {
	if n == 0 {
		return src, 0
	}

	matches := re.FindAllSubmatchIndex(src, n)
	if matches == nil {
		return src, 0
	}

	var result bytes.Buffer
	lastIndex := 0
	replacementCount := 0
	for _, match := range matches {
		result.Write(src[lastIndex:match[0]])
		submatches := make([][]byte, (len(match) / 2))
		for i := 0; i < len(match); i += 2 {
			if match[i] >= 0 && match[i+1] >= 0 {
				submatches[i/2] = src[match[i]:match[i+1]]
			} else {
				submatches[i/2] = nil
			}
		}
		result.Write(repl(match, submatches))
		lastIndex = match[1]
		replacementCount++
	}
	result.Write(src[lastIndex:])

	return result.Bytes(), replacementCount
}

// Quickly replace. Normally if you want to re-use the regex ptn then better compile the pattern first and used the
// standard lib regex replace func. This only save u some small typing.
//
// the 'repl' can contain capture using $1 or $2 for first group etc..
func ReplacePattern[T string | *regexp.Regexp](input []byte, pattern T, repl string, count int) ([]byte, int) {
	var re *regexp.Regexp
	switch v := any(pattern).(type) {
	case string:
		re = regexp.MustCompile(v)
	case *regexp.Regexp:
		re = v
	}

	replaceFunc := func(matchIndex []int, submatches [][]byte) []byte {
		expandedRepl := []byte(repl)
		for i, submatch := range submatches {
			if submatch != nil {
				placeholder := fmt.Sprintf("$%d", i)
				expandedRepl = bytes.Replace(expandedRepl, []byte(placeholder), submatch, -1)
			}
		}
		return expandedRepl
	}
	return ReplaceAllFuncN(re, input, replaceFunc, count)
}

// Same as ReplacePattern but do regex search and replace in a file
func SearchReplaceFile[T string | *regexp.Regexp](filename string, ptn T, repl string, count int, backup bool) int {
	finfo := Must(os.Stat(filename))
	fmode := finfo.Mode()
	if !(fmode.IsRegular()) {
		panic("CopyFile: non-regular destination file")
	}
	data := Must(os.ReadFile(filename))
	if backup {
		os.WriteFile(filename+".bak", data, fmode)
	}
	dataout, count := ReplacePattern(data, ptn, repl, count)
	CheckErr(os.WriteFile(filename, dataout, fmode), "SearchReplaceFile WriteFile")
	return count
}

// Same as ReplacePattern but operates on string rather than []byte
func SearchReplaceString[T string | *regexp.Regexp](instring string, ptn T, repl string, count int) string {
	o, _ := ReplacePattern([]byte(instring), ptn, repl, count)
	return string(o)
}

type LineInfileOpt struct {
	//string marker to insert the line after if regex or search string not found
	Insertafter string
	//string marker to insert the line above if regex or search string not found
	Insertbefore string
	// Line content - may contains capture group like $1
	Line string
	// Line number, if set just replace that line; ignore all options
	LineNo int
	Path   string
	// regex to match a line, if set and match line will be replaced. If not match line will be added based on location (after or before above)
	Regexp string
	// Same as regex but search raw string
	Search_string string
	// Default is 'present'. Set to absent to remove lines. This case regex or search string needed and all lines matched will be removed. Ignore all other opts
	State string
	// Backup the file or not. Default is false
	Backup bool
	// Keep backup files after number of days -
	KeepBackupDays int
	// Action for all pattern if set to true, otherwise only one line. Default is false
	ReplaceAll bool
}

func NewLineInfileOpt(opt *LineInfileOpt) *LineInfileOpt {
	if opt.State == "" {
		opt.State = "present"
		opt.KeepBackupDays = 90
	}
	if opt.Insertbefore == "" && opt.Insertafter == "" {
		opt.Insertbefore = "EOF"
	}
	return opt
}

// Simulate ansible lineinfile module. There are some difference intentionaly to avoid confusing behaviour and reduce complexbility.
// No option backref, the default behaviour is yes.
func LineInFile(filename string, opt *LineInfileOpt) (err error, changed bool) {
	var returnFunc = func(err error, changed bool) (error, bool) {
		// Clean up backup files after 90 days default
		GoFindExec([]string{"file://" + filepath.Dir(filename)}, []string{filename + `\.backup\-[\d]{4,4}[^\s]+`}, func(filename string, st fs.FileInfo) error {
			if st.ModTime().Before(time.Now().AddDate(0, 0, -opt.KeepBackupDays)) {
				return os.Remove(filename)
			}
			return nil
		})
		return err, changed
	}
	if opt.State == "" {
		opt.State = "present"
	}
	finfo, err := os.Stat(filename)
	if err1 := CheckErrNonFatal(err, "LineInFile Stat"); err1 != nil {
		return err1, false
	}
	fmode := finfo.Mode()
	if !(fmode.IsRegular()) {
		return fmt.Errorf("LineInFile: non-regular destination file %s", filename), false
	}
	if opt.Search_string != "" && opt.Regexp != "" {
		return fmt.Errorf("[ERROR] conflicting option. Search_string and Regexp can not be both set"), false
	}
	if opt.Insertafter != "" && opt.Insertbefore != "" {
		return fmt.Errorf("[ERROR] conflicting option. Insertafter and Insertbefore can not be both set"), false
	}
	if opt.LineNo > 0 && opt.Regexp != "" {
		return fmt.Errorf("[ERROR] conflicting option. LineNo and Regexp can not be both set"), false
	}
	data, err := os.ReadFile(filename)
	if err1 := CheckErrNonFatal(err, "LineInFile ReadFile"); err1 != nil {
		return err1, false
	}

	if opt.Backup && opt.State != "print" {
		if err := os.WriteFile(filename+".backup-"+time.Now().Format(TimeISO8601LayOut), data, fmode); err != nil {
			return err, false
		}
	}
	changed = false
	optLineB := []byte(opt.Line)
	datalines := bytes.Split(data, []byte("\n"))
	// ansible lineinfile is confusing. If set search_string and insertafter or inserbefore if search found the line is replaced and the other options has no effect. Unless search_string is not found then they will do it. Why we need that?
	// Basically the priority is search_string == regexp (thus they are mutually exclusive); and then insertafter or before. They can be all regex except search_string
	// If state is absent it remove all line matching the string, ignore the `line` param
	processAbsentLines := func(line_exist_idx map[int]any, index_list []int, search_string_found bool) (error, bool) {
		d, d2 := []string{}, map[int]string{}
		// fmt.Printf("DEBUG line_exist_idx %v index_list %v search_string_found %v\n", line_exist_idx, index_list, search_string_found)
		if len(line_exist_idx) == 0 && len(index_list) == 0 {
			return nil, false
		}
		for idx, l := range datalines {
			_l := string(l)
			d = append(d, _l)
			// line_exist_idx output of the case of matched the whole line
			if _, ok := line_exist_idx[idx]; ok {
				d2[idx] = _l
			}
		}
		// index_list is the outcome of the search_string/regex opt (search raw string).
		for _, idx := range index_list {
			if search_string_found {
				d2[idx] = d[idx] // remember the value to this map
			}
		}
		// fmt.Printf("DEBUG d2 %s\n", JsonDump(d2, "  "))
		if opt.State == "print" {
			o := map[string]any{
				"file":          filename,
				"matched_lines": d2,
			}
			fmt.Fprintf(os.Stdout, "%s\n", JsonDump(o, "  "))
		} else {
			for _, v := range d2 { // then remove by val here.
				d = RemoveItemByVal(d, v)
			}
			if err := os.WriteFile(filename, []byte(strings.Join(d, "\n")), fmode); err != nil {
				return err, false
			}
		}
		return nil, true
	}
	// Now we process case by case
	if opt.Search_string != "" || opt.LineNo > 0 { // Match the whole line or we have line number. This is derterministic behaviour
		search_string_found, line_exist_idx := true, map[int]any{}
		index_list := []int{}
		if opt.LineNo > 0 { // If we have line number we ignore the search string to be fast
			index_list = append(index_list, opt.LineNo-1)
		} else {
			for idx, lineb := range datalines {
				if bytes.Contains(lineb, []byte(opt.Search_string)) {
					index_list = append(index_list, idx)
				}
				if bytes.Equal(lineb, optLineB) { // Line already exists
					if opt.State == "present" {
						return returnFunc(nil, changed)
					} else {
						if !bytes.Equal(optLineB, []byte("")) {
							line_exist_idx[idx] = nil
						}
					}
				}
			}
		}
		if len(index_list) == 0 { // Did not find any search string. Will look insertafter  and before
			search_string_found = false
			ptnstring := opt.Insertafter

			if ptnstring == "" && opt.Insertbefore != "" {
				ptnstring = opt.Insertbefore
			}

			switch ptnstring {
			case "BOF":
				index_list = append(index_list, 0)
			case "EOF":
				index_list = append(index_list, len(datalines)-1)
			case "":
				return returnFunc(nil, false)
			default:
				ptn := regexp.MustCompile(ptnstring)
				for idx, lineb := range datalines {
					if ptn.Match(lineb) {
						index_list = append(index_list, idx)
					}
				}
			}
		}
		if len(index_list) == 0 && len(line_exist_idx) == 0 {
			// Can not find any insert_XXX match. Just add a new line at the end by setting this to the last
			index_list = append(index_list, len(datalines)-1)
		}
		switch opt.State {
		case "absent":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		case "present":
			last := index_list[len(index_list)-1]
			if search_string_found {
				if !opt.ReplaceAll {
					datalines[last] = optLineB
				} else {
					for _, idx := range index_list {
						datalines[idx] = optLineB
					}
				}
			} else {
				if opt.Insertafter != "" {
					datalines = InsertItemAfter(datalines, last, optLineB)
				} else if opt.Insertbefore != "" {
					datalines = InsertItemBefore(datalines, last, optLineB)
				} else { // to the end as always
					datalines = InsertItemAfter(datalines, last, optLineB)
				}
			}
			if err := os.WriteFile(filename, []byte(bytes.Join(datalines, []byte("\n"))), fmode); err != nil {
				return err, false
			}
			changed = true
		case "print":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		}
	}
	// Assume the behaviour is the same as search_string for Regex, just it is a regex now. So if it matches then the line matched will be replaced. If no match then process the insertbefore or after
	if opt.Regexp != "" {
		search_string_found := true
		regex_ptn := regexp.MustCompile(opt.Regexp)
		index_list := []int{}
		matchesMap := map[int][][]byte{}
		line_exist_idx := map[int]any{}

		for idx, lineb := range datalines {
			matches := regex_ptn.FindSubmatch(lineb)
			if len(matches) > 0 || matches != nil {
				index_list = append(index_list, idx)
				matchesMap[idx] = matches
			}
		}
		if len(index_list) == 0 { // Did not find any search string. Will look insertafter  and before
			search_string_found = false
			for idx, lineb := range datalines {
				if bytes.Equal(lineb, optLineB) { // Line already exists
					if opt.State == "present" {
						return returnFunc(nil, changed)
					} else {
						if !bytes.Equal(optLineB, []byte("")) {
							line_exist_idx[idx] = nil
						}
					}
				}
			}
			ptnstring := opt.Insertafter
			if ptnstring == "" {
				ptnstring = opt.Insertbefore
			}
			if ptnstring == "" {
				return returnFunc(nil, false)
			}
			ptn := regexp.MustCompile(ptnstring)
			for idx, lineb := range datalines {
				if ptn.Match(lineb) {
					index_list = append(index_list, idx)
				}
			}
		}
		if len(index_list) == 0 && len(line_exist_idx) == 0 {
			// Can not find any insert_XXX match. Just add a new line at the end by setting this to the last
			index_list = append(index_list, len(datalines)-1)
		}
		switch opt.State {
		case "absent":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		case "present":
			last := index_list[len(index_list)-1]
			if search_string_found {
				// Expanding submatch
				if !opt.ReplaceAll {
					for i, submatch := range matchesMap[last] {
						if submatch != nil {
							placeholder := fmt.Sprintf("$%d", i)
							optLineB = bytes.Replace(optLineB, []byte(placeholder), submatch, -1)
						}
					}
					datalines[last] = optLineB
				} else {
					for _, line := range index_list {
						for i, submatch := range matchesMap[line] {
							if submatch != nil {
								placeholder := fmt.Sprintf("$%d", i)
								optLineB = bytes.Replace(optLineB, []byte(placeholder), submatch, -1)
								datalines[line] = optLineB
							}
						}
					}
				}
			} else {
				if opt.Insertafter != "" {
					datalines = InsertItemAfter(datalines, last, optLineB)
				} else if opt.Insertbefore != "" {
					datalines = InsertItemBefore(datalines, last, optLineB)
				} else { // Insert to the last then :P
					datalines = InsertItemAfter(datalines, last, optLineB)
				}
			}
			if err := os.WriteFile(filename, []byte(bytes.Join(datalines, []byte("\n"))), fmode); err != nil {
				return err, false
			}
			changed = true
		case "print":
			return returnFunc(processAbsentLines(line_exist_idx, index_list, search_string_found))
		}
	}
	return err, changed
}

// ExtractTextBlock extract a text from two set regex patterns. The text started with the line matched start_pattern
// and when hit the match for end_pattern it will stop not including_endlines
func ExtractTextBlock(filename string, start_pattern, end_pattern []string) (block string, start_line_no int, end_line_no int, datalines []string) {
	datab := Must(os.ReadFile(filename))
	datalines = strings.Split(string(datab), "\n")

	found_start, found_end := false, false
	all_lines_count := len(datalines)

	found_start, start_line_no, _ = SearchPatternListInStrings(datalines, start_pattern, 0, all_lines_count, 0)
	if found_start {
		if start_line_no == all_lines_count-1 {
			found_end, end_line_no = true, all_lines_count
		} else {
			found_end, end_line_no, _ = SearchPatternListInStrings(datalines, end_pattern, start_line_no+1, all_lines_count, 0)
		}
		if found_end {
			outputlines := datalines[start_line_no:end_line_no]
			return strings.Join(outputlines, "\n"), start_line_no, end_line_no, datalines
		}
	}
	return
}

// SplitFirstLine return the first line from a text block. Line ending can be unix based or windows based.
// The rest of the block is return also as the second output
func SplitFirstLine[T string | []byte](data T) (T, T) {
	switch v := any(data).(type) {
	case string:
		text := v
		// Handle both \n and \r\n newlines
		if idx := strings.IndexAny(text, "\r\n"); idx != -1 {
			// Determine if the newline is \r\n or \n
			if idx+1 < len(text) && text[idx] == '\r' && text[idx+1] == '\n' {
				return T(text[:idx]), T(text[idx+2:]) // Skip \r\n
			}
			return T(text[:idx]), T(text[idx+1:]) // Skip \n
		}
		return T(text), T("") // If no newline, return the whole text as the first line
	case []byte:
		if idx := bytes.IndexAny(v, "\r\n"); idx != -1 {
			if idx+1 < len(v) && v[idx] == '\r' && v[idx+1] == '\n' {
				return T(v[:idx]), T(v[idx+2:])
			}
			return T(v[:idx]), T(v[idx+1:])
		}
		return T(v), T([]byte{})
	}
	return data, T([]byte{})
}

// Given a list of string of regex pattern and a list of string, find the coninuous match in that input list and return the start line of the match and the line content
//
// max_line defined the maximum line to search; set to 0 to use the len of input lines which is full
//
// start_line is the line to start searching; set to 0 to start from begining.
// start_line should be smaller than max_line
//
// direction is the direction of the search -1 is upward; otherwise is down. If it is not 0 then the value is used for the step jump while searching eg. 1 for every line, 2 for every
//
// 2 lines, -2 is backward every two lines
//
// If found match return true, the line no we match and the line content.
func SearchPatternListInStrings(datalines []string, pattern []string, start_line, max_line, direction int) (found_marker bool, start_line_no int, matchedPatterns []string) {
	total_lines := len(datalines)
	if len(pattern) == 0 || start_line >= total_lines {
		return false, -1, []string{}
	}
	marker_ptn := []*regexp.Regexp{}
	escapeMeta := os.Getenv("REGEXP_QUOTE_META")
	for _, ptn := range pattern {
		if escapeMeta == "YES" {
			ptn = regexp.QuoteMeta(ptn)
		}
		marker_ptn = append(marker_ptn, regexp.MustCompile(ptn))
	}
	expect_count_ptn_found := len(marker_ptn)
	count_ptn_found := 0
	if max_line == 0 {
		max_line = total_lines
	}
	step := 1
	if direction != 0 { // Allow caller to set the step
		step = direction
	}
datalines_Loop:
	for idx := start_line; idx < max_line && idx >= 0; idx = idx + step {
		count_ptn_found = 0
		_matches_lines := []string{}
		line := datalines[idx]
		// fmt.Fprintf(os.Stderr, "line:%d|step:%d - %s\n", idx, step, line)
		if marker_ptn[0].MatchString(line) { // Found first one. Lets look forward count_ptn_found-1 lines and see we got match
			count_ptn_found++
			_matches_lines = append(_matches_lines, line)
			for i := 1; i < expect_count_ptn_found; i++ {
				if idx+expect_count_ptn_found-1 >= max_line { // -1 because we already move 1 to get idx.
					// Can not look forward - out of bound. We reach end of line.
					matchedPatterns = append(matchedPatterns, _matches_lines...)
					break datalines_Loop
				}
				if marker_ptn[i].MatchString(datalines[idx+i]) {
					count_ptn_found++
					_matches_lines = append(_matches_lines, datalines[idx+i])
				} else {
					continue datalines_Loop
				}
			}
			found_marker, start_line_no = count_ptn_found == expect_count_ptn_found, idx
			matchedPatterns = append(matchedPatterns, _matches_lines...)
			return
		}
	}
	return
}

// ExtractLineInLines will find a line match a pattern with capture (or not). The pattern is in between a start pattern and end pattern to narrow down
//
// search range. Return the result of FindAllStringSubmatch func of the match line
//
// This is simpler as it does not support multiple pattern as a marker like the other func eg ExtractTextBlockContains so input should be small and pattern match should be unique. Use the other function to devide it into small range and then use this func.
//
// start and line can be the same pattern. Same as line and end; it will return the match of start (or end) pattern
func ExtractLineInLines(blocklines []string, start, line, end string) [][]string {
	p0, p1, p2 := regexp.MustCompile(start), regexp.MustCompile(line), regexp.MustCompile(end)
	found_start, found, found_end := false, false, false
	var l string
	// length := len(blocklines)
	for _, _l := range blocklines {
		if !found_start {
			found_start = p0.MatchString(_l)
			continue
		}
		if !found_end {
			found_end = p2.MatchString(_l)
		}
		if found_start && !found {
			found = p1.MatchString(_l)
			if found {
				l = _l
			}
		}
		if found_end {
			break
		}
	}
	if found {
		return p1.FindAllStringSubmatch(l, -1)
	} else {
		return nil
	}
}

// SplitTextByPattern splits a multiline text into sections based on a regex pattern.
//
// If includeMatch is true, the matching lines are included in the result.
//
// pattern should a multiline pattern like `(?m)^Header line.*`
func SplitTextByPattern(text, pattern string, includeMatch bool) []string {
	re := regexp.MustCompile(pattern)
	sections := []string{}

	switch includeMatch {
	case true:
		matches := re.FindAllStringIndex(text, -1)
		start := 0
		for _, match := range matches {
			if start < match[0] {
				_t := strings.TrimSpace(text[start:match[0]])
				if _t != "" {
					sections = append(sections, _t)
				}
				start = match[0]
			}
		}
		sections = append(sections, text[start:]) // Capture the remaining part of the text
	case false:
		splitText := re.Split(text, -1)
		for _, part := range splitText {
			part = strings.TrimSpace(part)
			if part != "" {
				sections = append(sections, part)
			}
		}
	}
	return sections
}

// Edit line in a set of lines using simple regex and replacement
func LineInLines(datalines []string, search_pattern string, replace string) (output []string) {
	search_pattern_ptn := regexp.MustCompile(search_pattern)
	for i := 0; i < len(datalines); i++ {
		datalines[i] = search_pattern_ptn.ReplaceAllString(datalines[i], replace)
	}
	return datalines
}

// ExtractTextBlockContains extracts a text block which contains marker which could be an int or a list of pattern.
//
// First we get the text from the line number or search for a match to the upper pattern. If we found we will search
// down for the marker if it is defined, and when found, search for the lower_bound_pattern.
//
// The marker should be in the middle.
//
// Return the text within the upper and lower, but not including the lower bound. Also return the line number range
// and full file content as datalines.
//
// upper and lower is important; you can ignore marker by using an empty []string{}.
func ExtractTextBlockContains(
	filename string,
	upper_bound_pattern, lower_bound_pattern []string,
	marker []string,
	start_line int,
) (block string, start_line_no int, end_line_no int, datalines []string, matchedPatterns [][]string) {

	// Read all lines from file
	f, err := os.Open(filename)
	if err != nil {
		return "", -1, -1, nil, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		datalines = append(datalines, scanner.Text())
	}

	total := len(datalines)
	matchedPatterns = make([][]string, 3) // [0]=upper matched, [1]=marker matched, [2]=lower matched

	// Helper: compile patterns and try to match a line, return matched pattern string or ""
	matchAny := func(line string, patterns []string) string {
		for _, pat := range patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			if re.MatchString(line) {
				return pat
			}
		}
		return ""
	}

	// Determine search start offset (1-based start_line, 0 means beginning)
	searchFrom := 0
	if start_line > 0 {
		searchFrom = start_line - 1
	}
	if searchFrom >= total {
		return "", -1, -1, datalines, matchedPatterns
	}

	// ── Step 1: Find upper bound ──────────────────────────────────────────────
	upperStart := -1

	if len(upper_bound_pattern) == 0 {
		// No upper pattern — start from start_line (or 0)
		upperStart = searchFrom
	} else {
		for i := searchFrom; i < total; i++ {
			if pat := matchAny(datalines[i], upper_bound_pattern); pat != "" {
				upperStart = i
				matchedPatterns[0] = append(matchedPatterns[0], pat)
				break
			}
		}
	}

	if upperStart == -1 {
		return "", -1, -1, datalines, matchedPatterns
	}

	// ── Step 2: Find marker (if provided) ────────────────────────────────────
	// marker must appear after the upper bound; if not found the block is invalid
	markerFound := len(marker) == 0 // trivially satisfied when no marker given

	if !markerFound {
		for i := upperStart + 1; i < total; i++ {
			if pat := matchAny(datalines[i], marker); pat != "" {
				markerFound = true
				matchedPatterns[1] = append(matchedPatterns[1], pat)
				break
			}
		}
	}

	if !markerFound {
		return "", -1, -1, datalines, matchedPatterns
	}

	// ── Step 3: Find lower bound ──────────────────────────────────────────────
	eofAllowed := false
	for _, pat := range lower_bound_pattern {
		if strings.Contains(pat, "EOF") {
			eofAllowed = true
			break
		}
	}

	lowerEnd := -1 // index of the line that IS the lower bound (excluded from block)

	if len(lower_bound_pattern) == 0 {
		// No lower pattern — block runs to EOF
		lowerEnd = total
	} else {
		for i := upperStart + 1; i < total; i++ {
			if pat := matchAny(datalines[i], lower_bound_pattern); pat != "" {
				lowerEnd = i
				matchedPatterns[2] = append(matchedPatterns[2], pat)
				break
			}
		}
		if lowerEnd == -1 && eofAllowed {
			lowerEnd = total
		}
	}

	if lowerEnd == -1 {
		return "", -1, -1, datalines, matchedPatterns
	}

	// ── Assemble block ────────────────────────────────────────────────────────
	// Include the upper bound line; exclude the lower bound line.
	start_line_no = upperStart + 1 // 1-based line number of the upper bound line
	end_line_no = lowerEnd         // equals the 1-based line number of the last *included* line
	// (lowerEnd is 0-based exclusive, so lowerEnd == 1-based last included)

	blockLines := datalines[upperStart:lowerEnd]
	block = strings.Join(blockLines, "\n")

	return block, start_line_no, end_line_no, datalines, matchedPatterns
}

// errBlock returns a sentinel error result: oldBlock carries a human-readable error
// message prefixed with "ERROR: " so the caller can detect failure via start == -1
// and inspect oldBlock for the reason.
func errBlock(format string, args ...any) (string, int, int, [][]string) {
	return "ERROR: " + fmt.Sprintf(format, args...), -1, -1, nil
}

// BlockInFile finds a block of text matching the given patterns and replaces it with replText.
// Returns the old block, start/end line numbers (1-based, end is the line just before the lower bound),
// and the matched patterns for each bound.
//
// On any error (file not found, backup failure, write failure, etc.) the function returns:
//   - oldBlock = "ERROR: <human-readable description>"
//   - start = -1, end = -1
//
// Callers detect failure with a simple `if start == -1` check, then read oldBlock for the reason.
// Note: start == -1 also means "block not found + text was appended" (not an error); distinguish
// these by checking whether oldBlock has the "ERROR: " prefix.
//
// If not care about marker pass an empty slice []string{}.
//
// To be sure of accuracy all patterns must uniquely identify the block. Recommend full-line matching
// (use anchors ^ and $). If lower_bound_pattern contains "EOF", reaching end-of-file counts as a match.
//
// extraArg is optional; accepted keys:
//
//	insertIfNotFound => bool  — insert replText if no block is found (default: true)
func BlockInFile(
	filename string,
	upper_bound_pattern, lower_bound_pattern []string,
	marker []string,
	replText string,
	keepBoundaryLines bool,
	backup bool,
	start_line int,
	extraArgs ...map[string]any,
) (oldBlock string, start, end int, matchedPattern [][]string) {

	// Parse optional extra args
	insertIfNotFound := true
	if len(extraArgs) > 0 && extraArgs[0] != nil {
		if v, ok := extraArgs[0]["insertIfNotFound"]; ok {
			if b, ok := v.(bool); ok {
				insertIfNotFound = b
			}
		}
	}

	// Extract the block.
	// ExtractTextBlockContains signals an unreadable file with startNo==-1 AND nil datalines.
	block, startNo, endNo, datalines, matched := ExtractTextBlockContains(
		filename, upper_bound_pattern, lower_bound_pattern, marker, start_line,
	)

	if startNo == -1 && datalines == nil {
		return errBlock("could not read file %q", filename)
	}

	oldBlock = block
	matchedPattern = matched

	// ── Block not found ───────────────────────────────────────────────────────
	if startNo == -1 {
		if !insertIfNotFound {
			// Caller opted out of insertion — not an error, just nothing to do.
			return oldBlock, -1, -1, matchedPattern
		}

		// Append replText at end of file.
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return errBlock("block not found and could not open %q for append: %v", filename, err)
		}
		defer f.Close()

		if _, err = fmt.Fprintln(f, replText); err != nil {
			return errBlock("block not found and could not append to %q: %v", filename, err)
		}

		// Successful insertion; indices are -1 to signal "was not found, text appended".
		return oldBlock, -1, -1, matchedPattern
	}

	start = startNo
	end = endNo

	// ── Optional backup ───────────────────────────────────────────────────────
	if backup {
		backupName := filename + ".bak"
		data, err := os.ReadFile(filename)
		if err != nil {
			return errBlock("could not read %q for backup: %v", filename, err)
		}
		if err = os.WriteFile(backupName, data, 0644); err != nil {
			return errBlock("could not write backup file %q: %v", backupName, err)
		}
	}

	// ── Build replacement line slice ──────────────────────────────────────────
	// startNo is the 1-based line number of the upper-bound line  → 0-based idx = startNo-1
	// endNo   is the 1-based number of the last included line     → 0-based exclusive = endNo
	// upperIdx: 0-based index of the upper-bound line.
	// lowerIdx: 0-based index of the lower-bound line (excluded from the old block).
	upperIdx := startNo - 1
	lowerIdx := endNo // points AT the lower-bound line

	var newLines []string

	// Lines strictly before the block (never includes upper boundary).
	newLines = append(newLines, datalines[:upperIdx]...)

	if keepBoundaryLines {
		// Retain upper-bound line, then replacement, then lower-bound line.
		newLines = append(newLines, datalines[upperIdx])
		if replText != "" {
			newLines = append(newLines, strings.Split(replText, "\n")...)
		}
		if lowerIdx < len(datalines) {
			newLines = append(newLines, datalines[lowerIdx])
		}
		// Continue from the line after the lower boundary.
		lowerIdx++
	} else {
		// Drop both boundary lines and the inner content; insert replacement.
		if replText != "" {
			newLines = append(newLines, strings.Split(replText, "\n")...)
		}
		// Skip past the lower-bound line.
		lowerIdx++
	}

	if lowerIdx < len(datalines) {
		newLines = append(newLines, datalines[lowerIdx:]...)
	}

	// ── Write back ────────────────────────────────────────────────────────────
	output := strings.Join(newLines, "\n")
	if len(datalines) > 0 && !strings.HasSuffix(output, "\n") {
		output += "\n"
	}

	if err := os.WriteFile(filename, []byte(output), 0644); err != nil {
		return errBlock("could not write %q: %v", filename, err)
	}

	return oldBlock, start, end, matchedPattern
}
