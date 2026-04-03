package cjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
)

// Marshal returns a canonical JSON encoding with lexicographically sorted object keys.
func Marshal(value any) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	if err := writeValue(buffer, normalize(value)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeValue(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buffer.Write(encoded)
	case json.Number:
		return writeNumber(buffer, string(typed))
	case float32:
		return writeFloat(buffer, float64(typed))
	case float64:
		return writeFloat(buffer, typed)
	case int, int8, int16, int32, int64:
		buffer.WriteString(fmt.Sprintf("%d", typed))
	case uint, uint8, uint16, uint32, uint64:
		buffer.WriteString(fmt.Sprintf("%d", typed))
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeValue(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buffer.Write(encodedKey)
			buffer.WriteByte(':')
			if err := writeValue(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		reflected := reflect.ValueOf(value)
		switch reflected.Kind() {
		case reflect.Slice, reflect.Array:
			items := make([]any, reflected.Len())
			for index := 0; index < reflected.Len(); index++ {
				items[index] = normalize(reflected.Index(index).Interface())
			}
			return writeValue(buffer, items)
		case reflect.Map:
			if reflected.Type().Key().Kind() != reflect.String {
				return fmt.Errorf("unsupported map key type: %s", reflected.Type().Key())
			}
			mapped := make(map[string]any, reflected.Len())
			iter := reflected.MapRange()
			for iter.Next() {
				mapped[iter.Key().String()] = normalize(iter.Value().Interface())
			}
			return writeValue(buffer, mapped)
		case reflect.Struct:
			encoded, err := json.Marshal(value)
			if err != nil {
				return err
			}
			var parsed any
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			if err := decoder.Decode(&parsed); err != nil {
				return err
			}
			return writeValue(buffer, parsed)
		default:
			return fmt.Errorf("unsupported value for canonicalization: %T", value)
		}
	}
	return nil
}

func normalize(value any) any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var parsed any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return value
	}
	return parsed
}

func writeNumber(buffer *bytes.Buffer, value string) error {
	if value == "" {
		return fmt.Errorf("unsupported non-finite JSON number")
	}
	buffer.WriteString(value)
	return nil
}

func writeFloat(buffer *bytes.Buffer, value float64) error {
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return fmt.Errorf("unsupported non-finite JSON number")
	}
	if value == math.Trunc(value) {
		buffer.WriteString(strconv.FormatInt(int64(value), 10))
		return nil
	}
	buffer.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	return nil
}
