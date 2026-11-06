package signingflow

import (
	"encoding/json"
	"strconv"
	"strings"
)

func grpcCode(body any) (int, bool) {
	record, ok := asMap(body)
	if !ok {
		return 0, false
	}
	return asInt(record["code"])
}

func serverMessage(body any) string {
	if text, ok := body.(string); ok {
		return text
	}
	record, ok := asMap(body)
	if !ok {
		return ""
	}
	return str(record["message"])
}

func traceCode(body any) string {
	return findMeta(body, "trace_code")
}

func resourceName(body any) string {
	if url := findMeta(body, "resource_url"); url != "" {
		return url
	}
	return findMeta(body, "resource_id")
}

func fieldViolations(body any) []FieldViolation {
	var found []FieldViolation
	walk(body, func(record map[string]any) {
		list, ok := record["fieldViolations"]
		if !ok {
			list = record["field_violations"]
		}
		items, ok := list.([]any)
		if !ok {
			return
		}
		for _, item := range items {
			row, ok := asMap(item)
			if !ok {
				continue
			}
			field := str(row["field"])
			description := str(row["description"])
			if field != "" || description != "" {
				found = append(found, FieldViolation{Field: field, Description: description})
			}
		}
	})
	return found
}

func mentionsIdempotency(body any) bool {
	encoded, err := json.Marshal(body)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(encoded)), "idempotency")
}

func findMeta(body any, key string) string {
	found := ""
	walk(body, func(record map[string]any) {
		if found != "" {
			return
		}
		meta, ok := asMap(record["metadata"])
		if !ok {
			return
		}
		if value := str(meta[key]); value != "" {
			found = value
		}
	})
	return found
}

func walk(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, child := range typed {
			walk(child, visit)
		}
	case []any:
		for _, child := range typed {
			walk(child, visit)
		}
	}
}

func asMap(value any) (map[string]any, bool) {
	record, ok := value.(map[string]any)
	return record, ok && record != nil
}

func str(value any) string {
	text, _ := value.(string)
	return text
}

func asInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	case string:
		parsed, err := strconv.Atoi(typed)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
