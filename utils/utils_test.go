package utils

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	p1 := Must(GenerateRandomBytes(35)) // Use bytes is fine and better if we dont case about printability
	// p1 := Must(base64.StdEncoding.EncodeToString(p))
	// println(string(p1))
	inputstr := "this is text"
	for _, encVer := range []byte{EncryptVersion1, EncryptVersion2} {
		cfg := Must(NewEncConfigForVersion(encVer))
		// cfg := DefaultEncryptionConfig()
		println(JsonDump(cfg, ""))
		// cfg.KDF = KDFScrypt // u can even change it
		o := Must(Encrypt(inputstr, p1, cfg))
		println("Encrypted: ", o)
		o1 := Must(Decrypt(o, p1, cfg))
		println("Decrypt result: ", o1)
		if o1 != inputstr {
			panic("[ERROR] decrypted not same as input\n")
		}
	}
}

func TestDecryptV0(t *testing.T) {
	cipher := ``
	println(Must(Decrypt_v0(cipher, ``)))

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
	// os.Setenv("CURL_DEBUG", "yes")
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
		Search_string: "This is new line insert at end ",
		Line:          "This is new line insert at end ",
		Insertafter:   "EOF",
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
	insert := true
	for {
		if seek > 0 {
			insert = false
		}
		o, start, end, matchedPattern := BlockInFile("../tests/input.yaml", []string{`^adfs_pass\: .*$`}, []string{`^[\s]*([^\d]*|\n|EOF)$`}, []string{`^[\s]+\$ANSIBLE_VAULT.*$`}, sourceBlock, true, false, seek, map[string]any{"insertIfNotFound": insert})
		if o == "" {
			break
		}
		println(o)
		seek = end
		println(start, end, JsonDump(matchedPattern, ""))
	}
	sourceBlock = `line 1
	line 2`
	seek = 0
	insert = true
	for {
		if seek > 0 {
			insert = false
		}
		o, start, end, matchedPattern := BlockInFile("../tests/input.yaml", []string{`#new lines block added`}, []string{`#new lines block end`}, []string{}, sourceBlock, true, false, seek, map[string]any{"insertIfNotFound": insert})
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
	oldcontent_enc := `qwqwqdwqdqwd`
	old_content := Must(Decrypt_v0(oldcontent_enc, key))
	println(Encrypt(old_content, key, nil))
}

func TestGoFindExec(t *testing.T) { // Example of fine tune the action to use GoFindExec one
	count := 0                     // Hold count
	fileList := map[int64]string{} // Hold the unix time and point to file name

	GoFindExec([]string{"file://."}, []string{`.*\.go`}, func(myfile string, stat fs.FileInfo) error {
		if stat.ModTime().Before(time.Now().AddDate(0, 0, -30)) {
			count++                                  // Store count
			fileList[stat.ModTime().Unix()] = myfile // Stored file list
		}
		return nil
	}) // Now we can use the fileList to do externally
	println("[INFO] count files ", count)

	filemodTimeList := MapKeysToSlice(fileList) // These sort the mod time in order ascending
	slices.SortFunc(filemodTimeList, func(a, b int64) int {
		return int(a - b)
	})
	for _, i := range filemodTimeList { // Now u can do anything with file name in i; you may keep a minimum if files, etc
		println(fileList[i], time.Unix(i, 0).Format(TimeISO8601LayOut))
	}

	// Simpler usage -
	GoFindExec([]string{"file://."}, []string{`.*\.go`}, func(myfile string, stat fs.FileInfo) error {
		if stat.ModTime().Before(time.Now().AddDate(0, 0, -30)) { // condition
			println(myfile) // action
		}
		return nil
	})
}

func TestRunSystemCmd(t *testing.T) {
	println(RunSystemCommand(`ls `, true))
	o, e := RunSystemCommandV2(`ls /something`, true)
	println(o)
	if e != nil {
		println(e.Error())
	}
}

func TestGrep(t *testing.T) {
	o, found := Grep(`kubeconfig_filename: {{ work_dir }}/files/shared-kubeconfig.yaml`, `kubeconfig_filename: .*\/([^\/]+)`, true, false)
	fmt.Printf("%v - %v\n", o, found)
	found = FileGrep(".", "ReadFile", "", false, false)
	println(found)
}

func TestGrepStream(t *testing.T) {
	data := `something in line1
	multiline to
	last line not matchg anything`
	inputReader := strings.NewReader(data)
	GrepStream(io.NopCloser(inputReader), `(something|multi)`, false, false, "", "")

}

func TestUseStdinForRunSystemCmd(t *testing.T) {
	destDir := Must(os.Getwd()) + "/" + uuid.New().String() + "test-tar"
	CheckErr(os.MkdirAll(destDir, 0o755), "")
	defer os.RemoveAll(destDir)
	// fifo := "/tmp/test-fifo"
	// os.RemoveAll(fifo)
	// unix.Mkfifo(fifo, uint32(0666))
	// start reader first
	var fifo io.WriteCloser
	go func() {
		cmd := exec.Command("tar", "xf", "-", "--zstd", "-C", destDir)
		// fd, err := os.OpenFile(fifo, os.O_RDONLY, 0600)
		// CheckErr(err, "")
		// cmd.Stdin = fd
		// cmd.Stdout = os.Stdout
		// cmd.Stderr = os.Stderr
		fifo = Must(cmd.StdinPipe())
		o, err := RunSystemCommandV3(cmd, true)
		CheckErr(err, "Error "+o)
		println(o)
	}()
	// Give reader time to start (important for FIFO)
	time.Sleep(200 * time.Millisecond)
	tarOpts := NewTarOptions().WithStripTopLevelDir(true).EnableCompression(true)
	CreateTarball([]string{"go.mod", "go.sum", "/home/stevek/tmp/goplay"}, fifo, tarOpts)
	// 4. Wait and verify
	time.Sleep(2 * time.Second)

	filepath.Walk(destDir, func(path string, info os.FileInfo, err error) error {
		fmt.Println("extracted:", path)
		return nil
	})

	if FileExistsV2(destDir+"/go.mod") != nil {
		t.Fatal("Can not find file go.mod in the dest dir: " + destDir + "/go.mod")
	}

	// Use dot . if we only want the dir content, but not the dir itself in sources
	CreateTarball("/home/stevek/tmp/1/.", destDir+"/test-create-tar.tar.zst", nil)

	CheckErr(os.MkdirAll(destDir+"/new-extract", 0o755), "")
	CheckErr(ExtractTarball(destDir+"/test-create-tar.tar.zst", destDir+"/new-extract", tarOpts), "")
	if FileExistsV2(destDir+"/new-extract/go.mod") != nil {
		t.Fatal("Can not find file go.mod in the dest dir new-extract")
	}
}

func TestSshExec(t *testing.T) {
	se := NewSshExec(&SshExec{
		SshExecHost: "localhost",
		SshKeyFile:  "/home/stevek/.ssh/id_rsa-home",
		SshUser:     "stevek",
	})
	o := Must(se.CopyFile("", "go.sum", "go.mod"))
	defer os.RemoveAll(o)
	if FileExistsV2(o+"/go.sum") != nil {
		t.Fatal("Copy failed")
	}
	o1 := Must(se.CopyDir("", "go.mod", "go.sum", "/home/stevek/tmp/go-pipe"))
	defer os.RemoveAll(o1)
	time.Sleep(1 * time.Second)
	if FileExistsV2(o1+"/go.sum") != nil {
		t.Fatal("Copy dir failed. Path: " + o1)
	}
	println(o1)
	o2 := Must(se.Exec(`ls /home
	echo "Running remotely multiple command"
	`))
	println(o2)
	o3 := Must(se.Exec(`ls /home/`))
	println(o3)
}

func TestSshExecGomod(t *testing.T) {
	se := NewSshExec(&SshExec{
		SshExecHost: "localhost",
		SshKeyFile:  "/home/stevek/.ssh/id_rsa-home",
		SshUser:     "stevek",
	})
	o, err := se.ExecGoMod(`/home/stevek/src/automation-go`, "pass-strength", "/home/stevek/src/golang-tools")
	if err != nil {
		t.Fatalf("[ERROR] %s - Output: %s", err.Error(), o)
	}
	println(o)
}

func TestConfigOverride(t *testing.T) {
	type MyCfg struct {
		SshExec
		MySrcDirs []string
	}
	myCfg := MyCfg{
		SshExec: *NewSshExec(&SshExec{
			SshExecHost: "localhost",
			SshKeyFile:  "/home/stevek/.ssh/id_rsa-home",
			SshUser:     "stevek",
		}),
		MySrcDirs: []string{"/home/stevek/tmp/go-pipe"},
	}
	o := Must(myCfg.CopyDir("", myCfg.MySrcDirs...))
	println(o)

}

func ExampleSha256SumFile() {
	fmt.Println(Sha256SumFile("tar.go"))
	// Output: 57a486ec3bfd0d0414cfbe29bc8297887326d0cf625cebb313382335c1bbcf64
}
