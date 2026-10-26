package sensitive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const canary = "canary-7f3a9c-do-not-leak"

type withExported struct {
	Name  string
	Value Value
}

type withUnexported struct {
	name  string
	value Value
}

type withPointer struct {
	Value *Value
}

func TestValueNeverPrintsContents(t *testing.T) {
	v := New(canary)

	outputs := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%T %v", "%10s", "%-10v"} {
		outputs["fmt "+verb] = fmt.Sprintf(verb, v)
	}
	outputs["fmt nested exported"] = fmt.Sprintf("%+v", withExported{Name: "x", Value: v})
	outputs["fmt nested exported #"] = fmt.Sprintf("%#v", withExported{Name: "x", Value: v})
	outputs["fmt nested unexported"] = fmt.Sprintf("%+v", withUnexported{name: "x", value: v})
	outputs["fmt nested unexported #"] = fmt.Sprintf("%#v", withUnexported{name: "x", value: v})
	outputs["fmt pointer"] = fmt.Sprintf("%+v", withPointer{Value: &v})
	outputs["fmt slice"] = fmt.Sprintf("%v", []Value{v, v})
	outputs["fmt map"] = fmt.Sprintf("%v", map[string]Value{"k": v})
	outputs["fmt println"] = fmt.Sprintln(v)
	outputs["error wrap"] = fmt.Errorf("failed for %v: %w", v, errors.New("boom")).Error()

	asJSON, err := json.Marshal(withExported{Name: "x", Value: v})
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	outputs["json"] = string(asJSON)

	asText, err := v.MarshalText()
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	outputs["text"] = string(asText)

	var slogBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&slogBuf, nil)).Info("msg", "value", v, "struct", withExported{Value: v})
	outputs["slog"] = slogBuf.String()

	var zapBuf bytes.Buffer
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&zapBuf),
		zap.DebugLevel,
	))
	logger.Info("msg",
		zap.Any("any", v),
		zap.Any("struct", withExported{Value: v}),
		zap.Stringer("stringer", v),
		zap.Object("object", v),
		zap.Reflect("reflect", withExported{Value: v}),
	)
	_ = logger.Sync()
	outputs["zap"] = zapBuf.String()

	for name, out := range outputs {
		if strings.Contains(out, canary) {
			t.Errorf("%s leaked the value: %s", name, out)
		}
		// A hex dump of the canary would also be a leak.
		if strings.Contains(strings.ToLower(out), fmt.Sprintf("%x", canary)) {
			t.Errorf("%s leaked the value as hex: %s", name, out)
		}
	}
}

func TestReveal(t *testing.T) {
	if got := New(canary).Reveal(); got != canary {
		t.Fatalf("Reveal() = %q, want the original text", got)
	}
	var zero Value
	if !zero.IsEmpty() || zero.Reveal() != "" || zero.Len() != 0 {
		t.Fatal("zero Value should be empty")
	}
	if New("abc").Len() != 3 {
		t.Fatal("Len() should count bytes")
	}
}
