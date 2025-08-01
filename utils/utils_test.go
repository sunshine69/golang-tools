package utils

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
)

// func TestUnzip(t *testing.T) {
// 	err := Unzip("Downloads/artifacts.zip", ".")
// 	CheckErr(err, "  ")
// }

func TestGenerateRandomBytes(t *testing.T) {
	println(GenerateRandomBytes(48))
}
func TestGenerateRandom(t *testing.T) {
	n := MakePassword(35)
	log.Println(n)
}

func TestEmail(t *testing.T) {
	SendMail("fromaddr", []string{"toaddr"}, "test Subject", "Hi, test email", []string{"/tmp/ad-hoc-pod.yaml"}, "mailserver:25", "", "", false)
}

func TestEncrypt(t *testing.T) {
	p := Must(GenerateRandomBytes(35)) // Use bytes is fine and better if we dont case about printability
	p1 := Must(base64.StdEncoding.DecodeString(p))
	// println(string(p1))
	inputstr := "this is text"
	cfg := Must(NewEncConfigForVersion(EncryptVersion1))
	// cfg.KDF = KDFScrypt // u can even change it
	o := Must(Encrypt(inputstr, string(p1), cfg))
	println("Encrypted: ", o)
	o1 := Must(Decrypt(o, string(p1), cfg))
	println("Decrypt result: ", o1)
	if o1 != inputstr {
		panic("[ERROR] decrypted not same as input\n")
	}
}

func TestDecrypt(t *testing.T) {
	cipher := ``
	Must(Decrypt_v0(cipher, ``))

}
func TestSha1Sum(t *testing.T) {
	o := Sha1Sum("1q2w3e")
	log.Println(o)
	Assert(o == "9ac20922b054316be23842a5bca7d69f29f69d77", "OK", true)
}

func TestSha256Sum(t *testing.T) {
	o := Sha256Sum("1q2w3e")
	log.Println(o)
	Assert(o == "c0c4a69b17a7955ac230bfc8db4a123eaa956ccf3c0022e68b8d4e2f5b699d1f", "OK", true)
}

func TestSha512Sum(t *testing.T) {
	o := Sha512Sum("1q2w3e")
	log.Println(o)
	Assert(o == "da2ca4a2b6616e28479a372752377f23a2361e1df855d881ac987341f837e3f260f6d5d68e40f0b1fb62d98e3309a3593b12314d6e7b91179642426709c5d6f5", "OK", true)
}

func TestBcryptHash(t *testing.T) {
	hashed, _ := BcryptHashPassword("1q2w3e", -1)
	log.Printf("Hash: %s\n", hashed)
	Assert(BcryptCheckPasswordHash("1q2w3e", hashed), "OK", false)
}

// go test -timeout 30s -run '^TestCurl$'  -v
func TestCurl(t *testing.T) {
	os.Setenv("INSECURE_SKIP_VERIFY", "yes")
	os.Setenv("CURL_DEBUG", "yes")
	o, err := Curl("GET", "https://kernel.org", "", "", []string{}, nil)
	CheckErr(err, "ERROR")
	log.Println(o)
}

func TestRemoveItem(t *testing.T) {
	o := RemoveItemByIndex([]interface{}{"a", 21, "3"}, 1)
	log.Printf("%s\n", JsonDump(o, "   "))
	o = RemoveItemByVal([]interface{}{"a", 21, "3"}, "3")
	log.Printf("%s\n", JsonDump(o, "   "))
}

func TestSplitTextByPattern(t *testing.T) {
	text := `Header 1
	This is some content
	for the first section.
	Header 2
	This is some content
	for the second section.

	Header 3
	This is some content
	for the third section.`

	sections := SplitTextByPattern(text, `(?m)Header.*`, false)
	for idx, r := range sections {
		fmt.Printf("Rows %d\n%s\n", idx+1, r)
	}

	fmt.Println("Done test")
}

func TestLineinfile(t *testing.T) {
	err, changed := LineInFile("../tests/test.yaml", NewLineInfileOpt(&LineInfileOpt{
		// Regexp:     `v1.0.1(.*)`,
		Search_string: "This is new line",
		Line:          "This is new line to be replaced at line 4",
		// ReplaceAll: true,
	}))
	CheckErr(err, "Error")
	fmt.Println(changed)
}

func TestPickLinesInFile(t *testing.T) {
	fmt.Println(strings.Join(PickLinesInFile("../tests/test.yaml", 0, -2), "\n"))
}

func TestReadFileToLines(t *testing.T) {
	fmt.Println(strings.Join(ReadFileToLines("../tests/test.yaml", true), "\n"))
}

func TestLineInLines(t *testing.T) {
	o, _, _, _, matchedPattern := ExtractTextBlockContains("../tests/test.yaml", []string{`- [^\s]+:[ ]?[^\s]*`}, []string{`- [^\s]+:[ ]?[^\s]*`}, []string{`helm_chart_resource_fact: "{{ helm_chart_resource }}"`}, 0)
	fmt.Printf("'%s'\n%s\n", o, JsonDump(matchedPattern, ""))
	r := LineInLines(strings.Split(o, "\n"), `- set_fact:`, `- ansible.builtin.set_fact: `)
	fmt.Printf("'%s'\n", strings.Join(r, "\n"))
}

func TestJoinFunc(t *testing.T) {
	// tmpl := template.Must(template.New("").Funcs(template.FuncMap{"join": func(inlist []string, sep string) string { return strings.Join(inlist, sep) }}).Parse(`<?php  var2 - {{.var2}} this is output {{ join .var1 ","}} - ?>`))
	// tmpl.Execute(os.Stdout, map[string]any{"var1": []string{"a", "b", "c"}, "var2": "Value var2"})
	o := GoTemplateString(`<?php  var2 - {{.var2}} this is output {{ join "," .var1 }} - ?>`, map[string]any{"var1": []string{"a", "b", "c"}, "var2": "Value var2"})
	println("[DEBUG]", o)
}

func BenchmarkGoTemplateString(b *testing.B) { // go template is about 6 times faster than the gonja version
	for n := 0; n < b.N; n++ {
		GoTemplateString(`<?php  var2 - {{.var2}} this is output {{ join "," .var1 }} - ?>`, map[string]any{"var1": []string{"a", "b", "c"}, "var2": "Value var2"})
	}
}

func TestLinesInBlock(t *testing.T) {
	textfile := "../tests/test.txt"
	_, start, end, blocklines, matchedPattern := ExtractTextBlockContains(textfile, []string{`5.2 Inclusions provided`}, []string{`Part 2 Standard Terms`}, []string{`6.3 Ending on`}, 0)
	block1 := blocklines[start:end]
	start_block_lines := ExtractLineInLines(block1, `6.3 Ending on`, `([\d]+\/[\d]+\/[\d]+)`, `Fixed term agreements only`)
	println(JsonDump(start_block_lines, ""), JsonDump(matchedPattern, ""))
	block, _, _, _, _ := ExtractTextBlockContains(textfile, []string{`Item 2.1 Tenant\/s`}, []string{`2.2 Address for service`}, []string{`1. Full name/s`}, 0)
	tenantBlocks := SplitTextByPattern(block, `(?m)[\d]\. Full name\/s ([a-zA-Z0-9\s]+)`, true)
	println(JsonDump(tenantBlocks, ""))
	lineblocks := []string{}
	for _, l := range tenantBlocks {
		sp := strings.Split(l, "\n")
		for _, l1 := range sp {
			l1 = strings.TrimSpace(l1)
			if l1 != "" {
				lineblocks = append(lineblocks, l1)
			}
		}
	}
	start_block_lines = ExtractLineInLines(lineblocks, `Item 2.1 Tenant`, `Full name\/s (.*)$`, `Emergency contact full name`)
	println(JsonDump(start_block_lines, ""))
	start_block_lines = ExtractLineInLines(lineblocks, `Emergency contact full name`, `Full name\/s (.*)$`, `Emergency contact full name`)
	println(JsonDump(start_block_lines, ""))
	tenantNamePtn := regexp.MustCompile(`(?m)[\d]\. Full name\/s (.*)`)
	tenantNames := []string{}
	for _, l := range tenantBlocks {
		parsed := tenantNamePtn.FindStringSubmatch(l)
		if parsed != nil {
			tenantNames = append(tenantNames, parsed[1])
		}
	}
	println("Tenants: ", JsonDump(tenantNames, ""))
}

func TestBlockInFile(t *testing.T) {
	sourceBlock := `	$ANSIBLE_VAULT;1.1;AES256
	66303565376366383235336465396530316631306663373530666339373438383231636362663533
	3162633036323135616165376537323264643834313664370a613838636530623530333438613633
	65336661636532663139343234386335383637366333376163613831643461316235656562336563
	3839626436656531340a366132613834396238326531636133356463303231393538313665393466
	3562`
	seek := 0
	for {
		o, start, end, matchedPattern := BlockInFile("../tests/input.yaml", []string{`^adfs_pass\: .*$`}, []string{`^[\s]*([^\d]*|\n|EOF)$`}, []string{`^[\s]+\$ANSIBLE_VAULT.*$`}, sourceBlock, true, false, seek)
		if o == "" {
			break
		}
		println(o)
		seek = end
		println(start, end, JsonDump(matchedPattern, ""))
	}
	// o := BlockInFile("../tests/input.yaml", []string{"key2\\: \\!vault \\|"}, []string{`^[^\s]+.*`}, []string{`ANSIBLE_VAULT`}, sourceBlock, true, false)
}

func TestSearchPatternListInStrings(t *testing.T) {
	datalines := ReadFileToLines("../tests/input.yaml", false)
	found, start, matchedLines := SearchPatternListInStrings(datalines, []string{`#block config files`}, 0, 0, 0)
	println(found, start, JsonDump(matchedLines, ""))
}

func TestExtractTextBlockContains(t *testing.T) {
	b, s, e, ls, matchedPattern := ExtractTextBlockContains("../tests/input.yaml", []string{`#block config files`}, []string{`#end block config files`}, []string{`config_files_secrets\\:`}, 13)
	println(b, s, e, JsonDump(ls, ""), JsonDump(matchedPattern, ""))
}

func TestGoTemplate(t *testing.T) {
	o := GoTemplateString(`#gotmpl:variable_start_string:'{$', variable_end_string:'$}'
	[
			{$ range $idx, $app := .packages -$}
			"{$ $app $}_config-pkg",
			"{$ $app $}"{$ if ne $idx (add (len $.packages) -1) $},{$ end $}
			{$ end -$}
			]`, map[string]any{"packages": []string{"p1", "p2"}})

	println(o)
}

func TestMigrateOldEncrypt(t *testing.T) {
	key := os.Getenv("KEY")
	oldcontent_enc := ``
	old_content := Must(Decrypt_v0(oldcontent_enc, key))
	println(Encrypt(old_content, key, nil))
}
