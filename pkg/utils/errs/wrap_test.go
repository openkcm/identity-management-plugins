package errs_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
)

func TestWrap(t *testing.T) {
	t.Run("Should return wrapped error", func(t *testing.T) {
		wrapped := errs.Wrap(errors.New("test1"), errors.New("test2"))
		assert.Error(t, wrapped)
	})
}

func TestWrapf(t *testing.T) {
	t.Run("Should return wrapped error string", func(t *testing.T) {
		wrapped := errs.Wrapf(errors.New("test1"), "test2")
		assert.Error(t, wrapped)
	})
}
