package cryptonic_test

import (
	"testing"

	"github.com/matryer/is"
	log "github.com/sirupsen/logrus"
)

func TestBasic(t *testing.T) {
	is := is.New(t)
	is.True(true)
}

// # Helper Funtions

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
