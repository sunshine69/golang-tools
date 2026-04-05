package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	// "github.com/melbahja/goph"
)

// The controller hosts can be linux/nix or windows with git bash installed. The remote hosts should be only nix OS with sshd running
// In theory remote hosts with git bash and sshd server installed should be ok
type SshExec struct {
	// Auto generated per each spawn
	SessionDir string
	SshClient  *ssh.Client
	// Remote host name to exec the gomod or command
	SshExecHost   string
	SshPort       string
	SshKeyFile    string
	SshCommonOpts string
	SshKnownHost  string
	SshUser       string
	// This will be auto generated and re-use per each NewSshExec instantiation
	SshConfigFilePath    string
	SshConfigFileContent string
	// Directory name which contains the package main and compilable into a exec file to exec on remote. See ExecGoMod func for more
	GoModDir    string
	CgoEnabled  string
	GoProxy     string
	HttpHeaders []string
}

// NewSshExec initializes a new SshExec and establishes the SSH connection
func NewSshExec(host, user, keyFile string, extraOpt ...string) (*SshExec, error) {
	varArgs := ParseVarArgs(extraOpt...)

	out := SshExec{
		SshExecHost: host,
		SshUser:     user,
		SshKeyFile:  keyFile,
	}
	if p, ok := varArgs["port"]; ok {
		out.SshPort = p
	} else {
		out.SshPort = "22"
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(os.Getenv("SSH_KEY_PASSPHRASE")))
			if err != nil {
				return nil, fmt.Errorf("unable to parse private key: %v", err)
			}
		}
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// In a production environment, you should use ssh.FixedHostKey or verify against known_hosts
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	out.SshClient, err = ssh.Dial("tcp", host+":"+out.SshPort, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	return &out, nil
}

// CopyFile copies file(s) to remote using SFTP. Filename will be retained.
// remotePath is a directory and will be created if it does not exist.
func (s *SshExec) CopyFile(remotePath string, srcPaths ...string) (out string, err error) {
	if len(srcPaths) == 0 {
		return "", fmt.Errorf("[ERROR] source is empty")
	}
	if s.SshClient == nil {
		return "", fmt.Errorf("[ERROR] SSH client not initialized. Call NewSshExec first")
	}

	if remotePath == "" {
		remotePath = fmt.Sprintf("/tmp/devops-ssh-copyfile-%s", uuid.New().String())
	}

	sftpClient, err := sftp.NewClient(s.SshClient)
	if err != nil {
		return "", fmt.Errorf("failed to create sftp client: %w", err)
	}
	defer sftpClient.Close()

	// Ensure remote directory exists
	err = sftpClient.MkdirAll(remotePath)
	if err != nil {
		return "", fmt.Errorf("failed to create remote dir: %w", err)
	}

	for _, src := range srcPaths {
		err = s.copySingleFile(sftpClient, src, remotePath)
		if err != nil {
			return "", err
		}
	}

	return remotePath, nil
}

func (s *SshExec) copySingleFile(sc *sftp.Client, srcPath string, remoteDir string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer srcFile.Close()

	info, err := srcFile.Stat()
	if err != nil {
		return err
	}

	if info.IsDir() {
		return fmt.Errorf("source %s is a directory, please use CopyDir instead", srcPath)
	}

	dstPath := filepath.Join(remoteDir, filepath.Base(srcPath))
	dstFile, err := sc.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %s: %w", dstPath, err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy content to %s: %w", dstPath, err)
	}
	s.CgoEnabled = Ternary(s.CgoEnabled == "", "1", s.CgoEnabled)
	return sc.Chmod(dstPath, info.Mode())
}

func NewSshExecUseCLI(s *SshExec) *SshExec {
	if s.SessionDir == "" {
		s.SessionDir = Must(os.MkdirTemp("", "devops-tool-ssh"))
	}
	if s.SshConfigFileContent == "" {
		s.SshConfigFileContent = GoTemplateString(`Host *
  ControlMaster auto
  ControlPath {{.sessionDir}}/%r@%h-%p
  ControlPersist 1h
`, map[string]any{
			"sessionDir": s.SessionDir,
		})
	}
	if s.SshConfigFilePath == "" {
		s.SshConfigFilePath = filepath.Join(s.SessionDir, "ssh-config")
		os.WriteFile(s.SshConfigFilePath, []byte(s.SshConfigFileContent), 0o600)
	}
	if s.SshCommonOpts == "" {
		// Allow RSA key to be in so old system works
		s.SshCommonOpts = fmt.Sprintf("-F '%s' -o IdentitiesOnly=yes -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", s.SshConfigFilePath)
	}
	s.CgoEnabled = Ternary(s.CgoEnabled == "", "1", s.CgoEnabled)

	return s
}

// Clean up the object
func (s *SshExec) Close() {
	os.RemoveAll(s.SessionDir)
}

// CopyDir copies local dir/files to remote using a streaming tar/zstd approach via SSH Session.
// Requires remote host has tar and zstd utils installed.
func (s *SshExec) CopyDir(remotePath string, srcPaths ...string) (out string, err error) {
	if len(srcPaths) == 0 {
		return "", fmt.Errorf("[ERROR] source is empty")
	}
	if s.SshClient == nil {
		return "", fmt.Errorf("[ERROR] SSH client not initialized")
	}

	if remotePath == "" {
		remotePath = fmt.Sprintf("/tmp/devops-tool-ssh-copydir-%s", uuid.New().String())
	}

	// 1. Create a session to run the remote command
	session, err := s.SshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create ssh session: %w", err)
	}
	defer session.Close()

	// 2. Setup remote command: create dir and prepare to receive tar stream
	// We use 'tar -xf - --zstd' to extract from stdin
	// If remote system does not have tar
	remoteCmd := fmt.Sprintf("mkdir -p %s && tar -xf - --z%s -C %s", remotePath, "std", remotePath)

	// 3. Connect the remote command's stdin to our local stdin pipe
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create session stdin pipe: %w", err)
	}

	// 4. Start the remote command
	if err := session.Start(remoteCmd); err != nil {
		return "", fmt.Errorf("failed to start remote tar command: %w", err)
	}

	// 5. Create the tarball locally and stream it into the session's stdin
	// We use a separate goroutine or a blocking call to ensure we write before Wait()
	tarOpt := NewTarOptions().WithStripTopLevelDir(true)

	// Create an error channel to capture errors from the streaming goroutine
	errChan := make(chan error, 1)

	go func() {
		// We wrap the stdin pipe in a WriteCloser to satisfy CreateTarball requirements
		// Note: CreateTarball must close the writer when done to signal EOF to tar
		err := CreateTarball(srcPaths, stdin, tarOpt)
		if err != nil {
			errChan <- err
		}
	}()

	// 6. Wait for the remote command to finish and check for errors
	// Wait() returns error if the remote command exited with non-zero status
	sessionErr := session.Wait()

	// Check if the streaming goroutine encountered an error
	streamErr := <-errChan

	if sessionErr != nil {
		return "", fmt.Errorf("remote tar command failed: %w", sessionErr)
	}
	if streamErr != nil {
		return "", fmt.Errorf("failed to create local tarball: %w", streamErr)
	}

	return remotePath, nil
}

// Copy file(s) to remote. Filename will be retained. remotePath is a directory and be created if not exists
// Use scp in the OS. Each file will spawn one scp thus if you copy multiple files/dirs, it is
// better to use the func CopyDir instead as it will use pipe to remote.
// If remotePath is empty a random tmp dir would be created and value return to be used for the next command
func (s *SshExec) CopyFileUseCLI(remotePath string, srcPaths ...string) (out string, err error) {
	if len(srcPaths) == 0 {
		return "", fmt.Errorf("[ERROR] source is empty")
	}
	if remotePath == "" {
		remotePath = fmt.Sprintf("/tmp/devops-tool-ssh-copyfile-%s", uuid.New().String())
	}
	out, err = RunSystemCommandV2(GoTemplateString(`
	SCP_CMD='scp -p -i {{.ssh_key_file}} {{.ssh_common_opts}}'
	ssh -i {{.ssh_key_file}} {{ .ssh_common_opts }} {{ .ssh_user }}@{{ .ssh_host }} mkdir -p {{ .remote_path }}
	{{ range $file := .srcPaths }}
	$SCP_CMD {{ $file }} {{ $.ssh_user }}@{{ $.ssh_host }}:{{ $.remote_path }}/{{ $file | basename }}
	{{ end }}
	`, map[string]any{
		"ssh_key_file":    s.SshKeyFile,
		"ssh_common_opts": s.SshCommonOpts,
		"ssh_host":        s.SshExecHost,
		"srcPaths":        srcPaths,
		"remote_path":     remotePath,
		"ssh_user":        s.SshUser,
	}), true)
	if err != nil {
		return
	}
	return remotePath, nil
}

// Copy local dir/files to remote. The remotePath does not have to exist, in that case it will be created. The dirname of srcPaths is preserved if it points to a directory. It can be a
// multiple file paths which will be copied to remotePath/<file-name>
//
// Use ssh exec and tar for compressing and extracting. Requires remote host has tar and zstd utils installed
//
// If remotePath is empty a random tmp dir would be created and value return to be used for the next command
func (s *SshExec) CopyDirUseCLI(remotePath string, srcPaths ...string) (out string, err error) {
	if len(srcPaths) == 0 {
		return "", fmt.Errorf("[ERROR] source is empty")
	}
	if remotePath == "" {
		remotePath = fmt.Sprintf("/tmp/devops-tool-ssh-copydir-%s", uuid.New().String())
	}
	cmdString := GoTemplateString(`set -e
	mkdir -p {{ .remote_path }}
	export SSH_CMD='ssh -i {{.ssh_key}} {{.ssh_common_opts}}'
	cat - | $SSH_CMD {{ .ssh_user }}@{{ .ssh_host }} "cat - | tar -xf - --zstd -C {{ .remote_path }}"
	`, map[string]any{
		"ssh_key":         s.SshKeyFile,
		"ssh_common_opts": s.SshCommonOpts,
		"ssh_host":        s.SshExecHost,
		"srcPaths":        srcPaths,
		"remote_path":     remotePath,
		"ssh_user":        s.SshUser,
	})
	cmd := exec.Command("bash", "-c", cmdString)

	var fifo io.WriteCloser
	go func() {
		fifo = Must(cmd.StdinPipe())
		out, err = RunSystemCommandV3(cmd, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %s", err.Error())
			return
		}
	}()
	time.Sleep(200 * time.Millisecond)

	tarOpt := NewTarOptions().WithStripTopLevelDir(true)
	err = CreateTarball(srcPaths, fifo, tarOpt)
	if err != nil {
		return "", err
	}

	return remotePath, nil
}

// Fetch (Download) from remote to local. If remote is a file doesnload the file. If a dir, download the whole dir.
// The dest dir is local dir and its contents are remote dir (if remote is a dir) or all remotes files/dir
// if any of the remote is a file. The path will be stripped, that is only filename, or dirname will be downloaded
// into dest dir
func (s *SshExec) Fetch(dest string, remoteSrc ...string) (out string, err error) {
	cmd := GoTemplateString(`set -e
	mkdir '{{.dest}}'
	SCP_CMD='scp -p -i {{.ssh_key_file}} {{.ssh_common_opts}} -r'
	{{ range $item := .remoteSrc }}
	$SCP_CMD '{{.remote_host}}:/{{$item}}' {{.dest}}/{{$item|basename}}
	{{ end }}
	`, map[string]any{
		"dest":            dest,
		"ssh_key_file":    s.SshKeyFile,
		"ssh_common_opts": s.SshCommonOpts,
		"remoteSrc":       remoteSrc,
		"remote_host":     s.SshExecHost,
	})
	return RunSystemCommandV2(cmd, true)
}

// Exec a command on remote host hostname via ssh. Multiline command supported
func (s *SshExec) Exec(commands string) (out string, err error) {
	commandList := strings.Split(commands, "\n")
	var command, remotePath string
	if len(commandList) > 1 {
		tempF := Must(os.MkdirTemp("", ""))
		defer os.RemoveAll(tempF)
		tempScript := filepath.Join(tempF, "remote-exec-cmd.sh")
		CheckErr(os.WriteFile(tempScript, []byte(commands), 0o750), "Write remote-exec-cmd.sh")
		remotePath = Must(s.CopyFile("", tempScript))
		command = remotePath + "/remote-exec-cmd.sh" // Explicit set it to Nix as we wont support remote host is windows
	} else {
		command = commandList[0]
	}
	out, err = RunSystemCommandV2(GoTemplateString(`set -e
	export SSH_CMD='ssh -i {{.ssh_key}} {{.ssh_common_opts}} -l {{ .ssh_user }}'
	$SSH_CMD "{{ .ssh_host }}" {{ .command }}
	rm -rf {{.remote_path}}
	`, map[string]any{
		"ssh_key":         s.SshKeyFile,
		"ssh_common_opts": s.SshCommonOpts,
		"ssh_host":        s.SshExecHost,
		"command":         command,
		"ssh_user":        s.SshUser,
		"remote_path":     remotePath,
	}), true)
	return
}

// Copy a local or a binary from a url to remoteWorkDir, and exec that bin in remoteWorkDir with execArgs
// if exebin started with http(s):// then download it locally first before copy to remote
// If remoteWorkDir is empty string, it will created as temporary and clean up later on
// If remoteWorkDir is preset then the binary in there be checked - if it exists and same sha256 with local, no copy will be
// done
func (s *SshExec) CopyAndExec(exebin, remoteWorkDir string, keepAndReuseExec bool, execArgs ...string) (out string, err error) {
	if remoteWorkDir == "" {
		if keepAndReuseExec {
			panic("[ERROR] can not set keepAndReuseExec when remoteWorkDir is not provided")
		}
		remoteWorkDir = uuid.NewString()
		defer s.Exec("rm -rf " + remoteWorkDir)
	}
	tempDir := Must(os.MkdirTemp("", ""))
	defer os.RemoveAll(tempDir)
	execName := filepath.Base(exebin)
	localExecPath := exebin

	if strings.HasPrefix(exebin, "http") {
		localExecPath = filepath.Join(tempDir, execName)
		Curl("GET", exebin, "", localExecPath, []string{}, nil, nil)
	}

	remoteExecPath := filepath.Join(remoteWorkDir, execName)

	if keepAndReuseExec {
		o, err1 := s.Exec(`sha256sum -b ` + remoteExecPath)
		if err1 != nil || strings.Fields(o)[0] != Sha256SumFile(localExecPath) { // does not exists or sha256 sum not matched
			Must(s.CopyFile(remoteWorkDir, localExecPath))
		}
	} else {
		Must(s.CopyFile(remoteWorkDir, localExecPath))
	}

	out, err = s.Exec(remoteExecPath)
	s.Exec(`rm -f ` + remoteExecPath)
	return
}

// Exec a gomod at the remote hostname. resourceUrl is the Url to fetch the go source code project.
// It will fetch resourceUrl if required locally and compile it, then copy the cli to remote
// end exec it with args
//
// resourceUrl ->
// If it start with wget+ then assume it is download url. We strip off the 'wget+' to get the url
// The last filename should be a tar ball and no root directory (that is the go.mod is at the root dir). We will download the file, extract it to a temp dir and chdir into it before build.
//
// # If it is normal directory path then it will use it directly for compile the cli
//
// All other case will be assumed as a git resource Url, See man git-clone for more. It will
// be passed to git clone command as is.
//
// The directory structure should be a valid go mod dir (it has go.mod and go.sum)
// a list of dirs named <gomodName> with a main.go compilable to a binary. If this is empty the the root dir will be used. The binary name is the go
// mod name when you run go mod init <name>
// the option GoModDir is the directory path leading to the go.mod and go.sum file, default empty, that is we use the root dir
// The args will be parsed to the execution
//
// It will fetch the resource, compile it and copy to remote to exec. Currently only Linux remote hosts supported
//
// Return command output and error
func (s *SshExec) ExecGoMod(resourceUrl, gomodName, remoteWorkDir string, args ...string) (out string, err error) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)

	srcDir := ""
	// outputCliPath := binary_name

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	defer os.Chdir(cwd)
	// Process srcDir
	switch {
	case FileExistsV2(resourceUrl) == nil:
		srcDir = resourceUrl

	case strings.HasPrefix(resourceUrl, "wget+"):
		if err := os.Chdir(tempDir); err != nil {
			return "", err
		}
		savedFileName := filepath.Join(tempDir, "tmp", uuid.NewString()+".tgz")
		defer os.RemoveAll(savedFileName)
		if o, err := Curl("GET", strings.TrimPrefix(resourceUrl, "wget+"), "", savedFileName, s.HttpHeaders, nil, nil); err != nil {
			return o, fmt.Errorf("[ERROR] download file - %s - Output: %s", err.Error(), o)
		}
		if o, err := RunSystemCommandV2(GoTemplateString(`mkdir -p '{{.work_dir}}/gomod_source'
tar xf '{{.saved_file_name}}' -C '{{.work_dir}}/gomod_source'
if [ "$?" != "0" ]; then
  tar xf '{{.saved_file_name}}' --zstd -C '{{.work_dir}}/gomod_source'
fi
		`, map[string]any{"saved_file_name": filepath.ToSlash(savedFileName), "work_dir": tempDir}), true); err != nil {
			return "", fmt.Errorf("[ERROR] %s - %s", err.Error(), o)
		}
		srcDir = filepath.Join(tempDir, "gomod_source")

	default: // git clone ops
		if err := os.Chdir(tempDir); err != nil {
			return "", err
		}
		if o, err := RunSystemCommandV2(GoTemplateString(`cd '{{.work_dir}}'
git clone --depth=1 --single-branch --no-tags {{.git_checkout_url}} gomod_source'
		`, map[string]any{"git_checkout_url": resourceUrl, "work_dir": tempDir}), true); err != nil {
			return "", fmt.Errorf("[ERROR] %s - %s", err.Error(), o)
		}
		srcDir = filepath.Join(tempDir, "gomod_source")
	}

	if err := (os.Chdir(srcDir)); err != nil {
		return "", fmt.Errorf("Chdir to %s", srcDir)
	}
	if out, err = RunSystemCommandV2(GoTemplateString(`set -e
cd '{{.srcDir}}'

export CGO_ENABLED={{.cgo_enabled}}

if [ '{{.go_proxy}}' != '' ]; then
  export GOPROXY="{{.go_proxy}}"
fi

export GOOS='{{ .goos }}'
if [ '{{.gomod_dir}}' != '' ]; then cd {{.gomod_dir}}; fi

go generate ./...
if [ '{{.gomod_name}}' != '' ]; then
	BINARY_NAME='{{.gomod_name|basename}}.exe'
	go build -buildvcs=false -trimpath -ldflags="-X main.version=$APP_VERSION -extldflags=-static -w -s" --tags "osusergo,netgo" -o "${BINARY_NAME}" {{.gomod_name}}/*.go
else
	BINARY_NAME=$(basename $(go list -m)).exe
	go build -buildvcs=false -trimpath -ldflags="-X main.version=$APP_VERSION -extldflags=-static -w -s" --tags "osusergo,netgo" -o "${BINARY_NAME}" .
fi
echo -n "${BINARY_NAME}" > {{.srcDir}}/binary-name.txt
		`, map[string]any{
		"srcDir":      srcDir,
		"gomod_name":  gomodName,
		"gomod_dir":   s.GoModDir,
		"cgo_enabled": s.CgoEnabled,
		"go_proxy":    s.GoProxy,
		"goos":        Getenv("GOOS", "linux"),
	}), true); err != nil {
		return out, fmt.Errorf("[ERROR] %s", err.Error())
	}
	binary_name_b, err := os.ReadFile(filepath.Join(srcDir, "binary-name.txt"))
	binary_name := string(binary_name_b)
	if err != nil {
		return "Can not get binary name", err
	}
	outputCliPath := filepath.Join(srcDir, binary_name)

	remotePath, err := s.CopyFile("", outputCliPath)
	if err != nil {
		return "", err
	}
	out, err = s.Exec(GoTemplateString(`set -e
		if [ '{{.remote_work_dir}}' != '' ]; then
			if [ ! -d '{{.remote_work_dir}}' ]; then
			  mkdir -p '{{.remote_work_dir}}'
			  CLEAN_WD='yes'
			fi
			cd {{.remote_work_dir}}
		else
			cd $(dirname '{{.remote_bin_path}}')
		fi

		{{.remote_bin_path}} {{ range $arg := .args }}{{$arg}} {{end}}
		cd
		rm -rf $( dirname {{.remote_bin_path}})
		if [ "$CLEAN_WD" == "yes" ]; then rm -rf '{{.remote_work_dir}}'; fi
	`, map[string]any{"remote_bin_path": remotePath + "/" + binary_name, "args": args, "remote_work_dir": remoteWorkDir}))
	if err != nil {
		return out, fmt.Errorf("[ERROR] Exec %s. Output: %s", err.Error(), out)
	}

	return out, nil
}

// Take local go template file, template it and copy to remote hosts. If the src has
// multilines then treat is as the template string.
// If dest is empty string or not absolute path, create a temp dir and template file into it
// return the remote templated file path
func (s *SshExec) GoTemplate(src, dest string, data map[string]any, mode os.FileMode) (remoteFilePath string, err error) {
	if !filepath.IsAbs(dest) {
		destDir := "/tmp/" + uuid.NewString()
		dest = filepath.Join(destDir, Ternary(dest == "", uuid.NewString(), dest))
	}
	if strings.IndexByte(src, '\n') == -1 {
		if s.SshExecHost == "localhost" || s.SshExecHost == "127.0.0.1" {
			GoTemplateFile(src, dest, data, mode)
			return dest, nil
		}
		GoTemplateFile(src, dest, data, mode)
		return s.CopyFile(dest, dest)
	} else {
		templatedSrc := GoTemplateString(src, data)
		if s.SshExecHost == "localhost" || s.SshExecHost == "127.0.0.1" {
			os.WriteFile(dest, []byte(templatedSrc), mode)
			return dest, nil
		}
		os.WriteFile(dest, []byte(templatedSrc), mode)
		_, err = s.CopyFile(dest, dest)
	}
	return dest, nil
}

/**
 * ParseVarArgs takes a variadic slice of strings and converts them into a map.
 * It assumes the pattern: [key1, value1, key2, value2, ...]
 *
 * If the number of arguments is odd, the last element is ignored (as it has no pair)
 * or you can handle it as a nil value depending on your preference.
 */
func ParseVarArgs(args ...string) map[string]string {
	result := make(map[string]string)

	// Iterate by 2, checking that i+1 is within bounds
	for i := 0; i+1 < len(args); i += 2 {
		key := args[i]
		value := args[i+1]
		result[key] = value
	}

	return result
}
