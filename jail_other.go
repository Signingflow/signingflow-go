//go:build !unix

package signingflow

import "errors"

func readJailed(root, requested string, maxBytes int64) ([]byte, error) {
	return nil, errors.New("nofollow")
}
