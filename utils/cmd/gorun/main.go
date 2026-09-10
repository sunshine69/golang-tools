package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

var debug bool

func run(dir, cmd string, args ...string) error {
	if debug {
		fmt.Fprintf(os.Stderr, "+ %s %v\n", cmd, args)
	}

	c := exec.Command(cmd, args...)
	c.Dir = dir

	if debug {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Stdin = os.Stdin
	} else {
		c.Stdout = io.Discard
		c.Stderr = io.Discard
		c.Stdin = os.Stdin
	}

	return c.Run()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func main() {
	if os.Getenv("GO_RUN_DEBUG") != "" {
		debug = true
	}

	if err := runScript(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", err.Error())
		os.Exit(1)
	}
}

func runScript() error {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go-run <file.go> [arguments...]")
		return fmt.Errorf("usage error")
	}

	src, err := filepath.Abs(os.Args[1])
	if err != nil {
		return fmt.Errorf("resolving source path: %w", err)
	}

	if filepath.Ext(src) != ".go" {
		return fmt.Errorf("input must be a .go file")
	}

	args := os.Args[2:]

	parentDir := filepath.Dir(src)
	if gomod, err := os.Stat(filepath.Join(parentDir, "go.mod")); err == nil && !gomod.IsDir() {
		// File inside a gomod dir. Just chdir into that and run the project
		return buildAndRunBinary(parentDir, ".", args...)
	}

	tmp, err := os.MkdirTemp("", "go-run-*")
	if err != nil {
		return fmt.Errorf("creating temp directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	if debug {
		fmt.Println("Working directory:", tmp)
	}

	mainFile := filepath.Join(tmp, "main.go")

	if err := copyFile(src, mainFile); err != nil {
		return fmt.Errorf("copying source file: %w", err)
	}
	return buildAndRunBinary(tmp, mainFile, args...)
}

func buildAndRunBinary(tmp, mainFile string, args ...string) error {
	// Resolve dependencies
	if err := run(tmp,
		"go",
		"mod",
		"tidy",
	); err != nil {
		return fmt.Errorf("resolving dependencies: %w", err)
	}

	// Build executable
	bin := filepath.Join(tmp, "gorun-app")

	if err := run(tmp,
		"go",
		"build",
		"-o",
		bin,
		mainFile,
	); err != nil {
		return fmt.Errorf("building executable: %w", err)
	}

	// Execute
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = wd
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("script exited with code %d", exitErr.ExitCode())
		}
		return fmt.Errorf("executing binary: %w", err)
	}

	return nil
}
