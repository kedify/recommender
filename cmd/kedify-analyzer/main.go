package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kedify/recommender/analysis"
)

const (
	protocolVersion = "kedify-analyzer/v1"
	// Keep one local snapshot request bounded without constraining normal cluster inputs.
	maxRequestBytes = 16 << 20
	exitSuccess     = 0
	exitInternal    = 1
	exitInvalid     = 2
)

var version = "dev"

type request struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Input           analysis.Input  `json:"input"`
	Policy          analysis.Policy `json:"policy"`
}

type response struct {
	ProtocolVersion     string          `json:"protocolVersion"`
	AnalyzerVersion     string          `json:"analyzerVersion"`
	EngineVersion       string          `json:"engineVersion"`
	InputSchemaVersion  string          `json:"inputSchemaVersion"`
	OutputSchemaVersion string          `json:"outputSchemaVersion"`
	Output              analysis.Output `json:"output"`
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	requestBytes, err := io.ReadAll(io.LimitReader(stdin, maxRequestBytes+1))
	if err != nil {
		writeDiagnostic(stderr, "unable to read request: %v", err)
		return exitInvalid
	}
	if len(requestBytes) > maxRequestBytes {
		writeDiagnostic(stderr, "request exceeds %d-byte limit", maxRequestBytes)
		return exitInvalid
	}

	decoder := json.NewDecoder(bytes.NewReader(requestBytes))
	decoder.DisallowUnknownFields()

	var req request
	if err := decoder.Decode(&req); err != nil {
		writeDiagnostic(stderr, "invalid request: %v", err)
		return exitInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeDiagnostic(stderr, "invalid request: expected one JSON object")
		return exitInvalid
	}
	if req.ProtocolVersion != protocolVersion {
		writeDiagnostic(stderr, "unsupported protocolVersion %q; expected %q", req.ProtocolVersion, protocolVersion)
		return exitInvalid
	}

	output, err := analysis.Analyze(req.Input, req.Policy)
	if err != nil {
		writeDiagnostic(stderr, "analysis failed: %v", err)
		return exitInvalid
	}

	result := response{
		ProtocolVersion:     protocolVersion,
		AnalyzerVersion:     version,
		EngineVersion:       analysis.ResourceRightSizeDetectorVersion,
		InputSchemaVersion:  analysis.InputSchemaVersion,
		OutputSchemaVersion: analysis.OutputSchemaVersion,
		Output:              output,
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		writeDiagnostic(stderr, "unable to write response: %v", err)
		return exitInternal
	}
	return exitSuccess
}

func writeDiagnostic(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, "kedify-analyzer: "+format+"\n", args...)
}
