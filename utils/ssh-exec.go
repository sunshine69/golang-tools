package utils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	// "github.com/melbahja/goph"
)

type SshExec struct {
	SshExecHost   string
	SshKeyFile    string
	SshCommonOpts string
	SshKnownHost  string
	SshUser       string
}

func NewSshExec(s *SshExec) *SshExec {
	if s.SshCommonOpts == "" {
		s.SshCommonOpts = "-o IdentitiesOnly=yes -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
	}
	return s
}

// Copy file(s) to remote. Filename will be retained. remotePath is a directory and be created if not exists
// Use scp in the OS. Each file will spawn one scp thus if you copy multiple files/dirs, it is
// better to use the func CopyDir instead as it will use pipe to remote.
// If remotePath is empty a random tmp dir would be created and value return to be used for the next command
func (s *SshExec) CopyFile(remotePath string, srcPaths ...string) (out string, err error) {
	if len(srcPaths) == 0 {
		return "", fmt.Errorf("[ERROR] source is empty")
	}
	if remotePath == "" {
		remotePath = fmt.Sprintf("/tmp/devops-tool-ssh-copyfile-%s", uuid.New().String())
	}
	out, err = RunSystemCommandV2(GoTemplateString(`
	export SCP_CMD='scp -p -i {{.ssh_key_file}} {{.ssh_common_opts}}'
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
func (s *SshExec) CopyDir(remotePath string, srcPaths ...string) (out string, err error) {
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

// Exec a command on remote host hostname via ssh. Multiline command supported
func (s *SshExec) Exec(commands string) (out string, err error) {
	commandList := strings.Split(commands, "\n")
	var command, remotePath string
	if len(commandList) > 1 {
		tempF := Must(os.MkdirTemp("", ""))
		defer os.RemoveAll(tempF)
		CheckErr(os.WriteFile(tempF+"/remote-exec-cmd.sh", []byte(commands), 0o750), "Write remote-exec-cmd.sh")
		remotePath = Must(s.CopyFile("", tempF+"/remote-exec-cmd.sh"))
		command = remotePath + "/remote-exec-cmd.sh"
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

// Exec a gomod at the remote hostname. resourceUrl is the Url to fetch the go source code project.
// If it start with ssh:// then assume it is git url.
// If started with git+https:// then assume it is git with http (the git+ will be stripped).
// If started with http(s) then it will make a GET to that url to download.
// The last filename should be a tar ball and no root the directory
//
// The directory structure should be a valid go mod dir (it has go.mod and go.sum) with multiple directory representing each go cli and
// supplied as gomodName
// The args will be parsed to the execution
//
// It will fetch the resource, compile it and copy to remote to exec. Currently only Linux remote hosts supported
// Return command output and error
func ExecGoMod(hostname, resourceUrl, gomodName string, args ...string) (out string, err error) {

	return "TODO", nil
}
