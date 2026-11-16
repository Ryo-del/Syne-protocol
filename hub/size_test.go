package hub

import (
	"encoding/json"
	"testing"
)

// Размер конверта растёт линейно с числом устройств-получателей; предел MaxEnvelopeBytes
// должен вмещать группу из MaxGroupMembers участников с двумя устройствами у каждого.
func TestEnvelopeSizeFitsMaxGroup(t *testing.T) {
	sender, _ := GenerateDeviceKey()
	var rcpts []Certificate
	for i := 0; i < 2*MaxGroupMembers; i++ {
		d, _ := GenerateDeviceKey()
		rcpts = append(rcpts, Certificate{Version: Version, Login: "u@o", DeviceID: d.DeviceID(), SignPub: d.SignPub, AgreePub: d.AgreePub})
	}
	env, err := Seal([]byte("короткое сообщение"), []byte("group:7"), sender, rcpts)
	must(t, err)
	raw, _ := json.Marshal(env)
	t.Logf("конверт на %d устройств: %d байт", len(rcpts), len(raw))
	if len(raw) > MaxEnvelopeBytes {
		t.Fatalf("конверт %d байт не помещается в предел %d", len(raw), MaxEnvelopeBytes)
	}
}
