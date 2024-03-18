package main

// Surprisingly, the Go stdlib does not have a PKCS7 padding implementation, so we roll our own.

import (
	"bytes"
	"fmt"
)

// Pads the payload according to PKCS#7 specification.
func Pkcs7Pad(src []byte, blockSize int) ([]byte, error) {
	// Only allow 1-255 sized blocks as per standard.
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}

	// If the source is exactly the same size as the block size,
	// we need full block of padding.
	padLen := blockSize - len(src)%blockSize

	padding := []byte{byte(padLen)}
	padding = bytes.Repeat(padding, padLen)

	return append(src, padding...), nil
}

// Un-pads the payload according to PKCS#7 specification.
func Pkcs7UnPad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, fmt.Errorf("no data to un-pad")
	}

	// Last byte is the padding length.
	padLen := int(src[length-1])
	if padLen == 0 {
		// There is no such thing as 0-length padding.
		return nil, fmt.Errorf("invalid padding (last byte of the payload is zero)")
	}
	// If the last byte is more than the total length, this is invalid.
	if padLen > length {
		return nil, fmt.Errorf("invalid padding (last byte of the payload is greater than the payload length)")
	}

	origLen := length - padLen

	// Verify the padding matches the spec (all bytes must be the same).
	padding := src[origLen:]

	for i := 0; i < padLen; i++ {
		if padding[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding (padding bytes do not match)")
		}
	}

	// All good
	return src[:origLen], nil
}
