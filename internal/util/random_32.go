package util

import (
	"crypto/rand"
	"io"
	"reflect"
)

func Random32Bytes() [32]byte {
	randBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, randBytes)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return [32]byte(randBytes)
}

func ToByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return arr
}
