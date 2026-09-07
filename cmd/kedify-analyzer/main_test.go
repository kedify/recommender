package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kedify/recommender/analysis"
)

func TestAnalyzerExecutable(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "kedify-analyzer")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build analyzer: %v\n%s", err, output)
	}

	requestBytes := validRequest(t)
	first := executeAnalyzer(t, binary, requestBytes, exitSuccess)
	second := executeAnalyzer(t, binary, requestBytes, exitSuccess)
	if !bytes.Equal(first.stdout, second.stdout) {
		t.Fatalf("same request produced different output\nfirst: %s\nsecond: %s", first.stdout, second.stdout)
	}
	if len(first.stderr) != 0 {
		t.Fatalf("successful analysis wrote diagnostics: %s", first.stderr)
	}

	var got response
	if err := json.Unmarshal(first.stdout, &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ProtocolVersion != protocolVersion || got.AnalyzerVersion != "dev" ||
		got.EngineVersion != analysis.ResourceRightSizeDetectorVersion ||
		got.InputSchemaVersion != analysis.InputSchemaVersion || got.OutputSchemaVersion != analysis.OutputSchemaVersion {
		t.Fatalf("unexpected response metadata: %#v", got)
	}

	expectedBytes, err := os.ReadFile("../../analysis/testdata/default-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected analysis.Output
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Output, expected) {
		t.Fatalf("analyzer output differs from engine fixture\ngot: %#v\nwant: %#v", got.Output, expected)
	}

	tests := []struct {
		name   string
		input  string
		stderr string
	}{
		{name: "missing protocol", input: `{}`, stderr: `unsupported protocolVersion ""`},
		{name: "incompatible protocol", input: `{"protocolVersion":"kedify-analyzer/v2"}`, stderr: `unsupported protocolVersion "kedify-analyzer/v2"`},
		{name: "missing schema", input: `{"protocolVersion":"kedify-analyzer/v1"}`, stderr: `unsupported input schema version ""`},
		{name: "incompatible schema", input: `{"protocolVersion":"kedify-analyzer/v1","input":{"schemaVersion":"resource-analysis-input/v2"}}`, stderr: `unsupported input schema version "resource-analysis-input/v2"`},
		{name: "invalid analysis input", input: `{"protocolVersion":"kedify-analyzer/v1","input":{"schemaVersion":"resource-analysis-input/v1"}}`, stderr: `observedIntervalHours must be greater than 0`},
		{name: "unknown field", input: `{"protocolVersion":"kedify-analyzer/v1","unexpected":true}`, stderr: `unknown field "unexpected"`},
		{name: "malformed JSON", input: `{"protocolVersion":`, stderr: `invalid request`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := executeAnalyzer(t, binary, []byte(test.input), exitInvalid)
			if len(result.stdout) != 0 {
				t.Fatalf("invalid request wrote machine output: %s", result.stdout)
			}
			if !strings.Contains(string(result.stderr), test.stderr) {
				t.Fatalf("stderr = %q, want substring %q", result.stderr, test.stderr)
			}
		})
	}

	t.Run("oversized input", func(t *testing.T) {
		result := executeAnalyzer(t, binary, bytes.Repeat([]byte(" "), maxRequestBytes+1), exitInvalid)
		if len(result.stdout) != 0 {
			t.Fatalf("oversized request wrote machine output: %s", result.stdout)
		}
		if !strings.Contains(string(result.stderr), "request exceeds 16777216-byte limit") {
			t.Fatalf("unexpected stderr: %s", result.stderr)
		}
	})
}

func TestRunReturnsInternalErrorWhenResponseCannotBeWritten(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(bytes.NewReader(validRequest(t)), errorWriter{}, &stderr); code != exitInternal {
		t.Fatalf("run() = %d, want %d", code, exitInternal)
	}
	if !strings.Contains(stderr.String(), "unable to write response") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func validRequest(t *testing.T) []byte {
	t.Helper()
	inputBytes, err := os.ReadFile("../../analysis/testdata/default-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var input analysis.Input
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		t.Fatal(err)
	}
	requestBytes, err := json.Marshal(request{ProtocolVersion: protocolVersion, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	return requestBytes
}

type execution struct {
	stdout []byte
	stderr []byte
}

func executeAnalyzer(t *testing.T, binary string, input []byte, wantExit int) execution {
	t.Helper()
	cmd := exec.Command(binary)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	gotExit := exitSuccess
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("execute analyzer: %v", err)
		}
		gotExit = exitError.ExitCode()
	}
	if gotExit != wantExit {
		t.Fatalf("exit code = %d, want %d; stderr: %s", gotExit, wantExit, stderr.String())
	}
	return execution{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
