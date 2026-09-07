package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kedify/recommender/analysis"
)

const (
	protocolVersion = "kedify-analyzer/v1"
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
	decoder := json.NewDecoder(stdin)
	decoder.DisallowUnknownFields()

	var req request
	if err := decoder.Decode(&req); err != nil {
		fmt.Fprintf(stderr, "kedify-analyzer: invalid request: %v\n", err)
		return exitInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		fmt.Fprintln(stderr, "kedify-analyzer: invalid request: expected one JSON object")
		return exitInvalid
	}
	if req.ProtocolVersion != protocolVersion {
		fmt.Fprintf(stderr, "kedify-analyzer: unsupported protocolVersion %q; expected %q\n", req.ProtocolVersion, protocolVersion)
		return exitInvalid
	}

	output, err := analysis.Analyze(req.Input, req.Policy)
	if err != nil {
		fmt.Fprintf(stderr, "kedify-analyzer: analysis failed: %v\n", err)
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
		fmt.Fprintf(stderr, "kedify-analyzer: unable to write response: %v\n", err)
		return exitInternal
	}
	return exitSuccess
}
