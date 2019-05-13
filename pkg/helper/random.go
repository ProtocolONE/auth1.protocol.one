package helper

import (
	"math/rand"
	"time"
)

var (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = uint(6)
	letterIdxMask = uint64(1<<letterIdxBits - 1)
	letterIdxMax  = 63 / letterIdxBits
	src           = rand.NewSource(time.Now().UnixNano())
)

// GetRandString create and return random alphanumeric strings fixed length.
func GetRandString(length int) string {
	b := make([]byte, length)
	for i, cache, remain := length-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(uint64(cache) & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
