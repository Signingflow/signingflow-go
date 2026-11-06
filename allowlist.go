package signingflow

import _ "embed"
import "encoding/json"

//go:embed resources/allowlist.json
var allowlistJSON []byte

// Operation is one allowlisted API call.
type Operation struct {
	OperationID string `json:"operationId"`
	HTTP        string `json:"http"`
	Path        string `json:"path"`
	Idempotent  bool   `json:"idempotent"`
	Capability  string `json:"capability"`
}

var operations map[string]Operation

func init() {
	var doc struct {
		Operations []Operation `json:"operations"`
	}
	if err := json.Unmarshal(allowlistJSON, &doc); err != nil {
		panic(err)
	}
	operations = make(map[string]Operation, len(doc.Operations))
	for _, op := range doc.Operations {
		operations[op.OperationID] = op
	}
}

func operation(id string) Operation {
	return operations[id]
}
