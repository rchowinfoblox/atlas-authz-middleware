package grpc_opa_middleware

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func Test_JsonDecoding(t *testing.T) {
	type myType map[string][]string
	aOriginal := myType{
		"k1": { "k1e0", "k1e1", },
		"k2": { "k2e0", "k2e1", },
	}

	aJson, _ := json.Marshal(aOriginal)
	t.Logf("aJson=%s", aJson)

	var aUnmarshaled myType
	json.Unmarshal(aJson, &aUnmarshaled)
	t.Logf("aUnmarshaled=%#v", aUnmarshaled)
	if !reflect.DeepEqual(aOriginal, aUnmarshaled) {
		t.Errorf("aOriginal=%#v\naUnmarshaled=%#v", aOriginal, aUnmarshaled)
	}

	dec := json.NewDecoder(strings.NewReader(string(aJson)))
	var aDecoded myType
	dec.Decode(&aDecoded)
	t.Logf("aDecoded=%#v", aDecoded)
	if !reflect.DeepEqual(aOriginal, aDecoded) {
		t.Errorf("aOriginal=%#v\naDecoded=%#v", aOriginal, aDecoded)
	}

	unmarshalInterface := func(jsonBytes []byte, outp interface{}) error {
		return json.Unmarshal(jsonBytes, outp)
	}

	decodeInterface := func(jsonBytes []byte, outp interface{}) error {
		dec := json.NewDecoder(strings.NewReader(string(jsonBytes)))
		return dec.Decode(outp)
	}

	var iUnmarshaled myType
	unmarshalInterface(aJson, &iUnmarshaled)
	t.Logf("iUnmarshaled=%#v", iUnmarshaled)
	if !reflect.DeepEqual(aOriginal, iUnmarshaled) {
		t.Errorf("aOriginal=%#v\niUnmarshaled=%#v", aOriginal, iUnmarshaled)
	}

	var iDecoded myType
	decodeInterface(aJson, &iDecoded)
	t.Logf("iDecoded=%#v", iDecoded)
	if !reflect.DeepEqual(aOriginal, iDecoded) {
		t.Errorf("aOriginal=%#v\niDecoded=%#v", aOriginal, iDecoded)
	}
}
