package errors_test

import (
	stderrors "errors"
	"io"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/retry"
)

// A failed retry is New(attempts).Base(ErrRetryFailed): Unwrap leads only to ErrRetryFailed, and
// errors.Is does not find the dial error. YozhCauses does.
func TestYozhCausesHoldsTheAttemptsOfARetry(t *testing.T) {
	refused := syscall.Errno(10061)
	err := retry.Timed(2, 0).On(func() error { return refused })
	var xe *errors.Error
	if !stderrors.As(err, &xe) {
		t.Fatalf("retry.On returned %T, not *errors.Error", err)
	}
	if stderrors.Is(err, refused) {
		t.Fatal("errors.Is finds the attempt: then the classifier would not need YozhCauses")
	}
	causes := xe.YozhCauses()
	if len(causes) != 1 || causes[0] != refused {
		t.Fatalf("causes = %v, want [%v]", causes, refused)
	}
}

func TestYozhCausesTakesSingleErrorsOfTheMessage(t *testing.T) {
	causes := errors.New("dial: ", io.EOF, " then ", 7).YozhCauses()
	if len(causes) != 1 || causes[0] != io.EOF {
		t.Fatalf("causes = %v, want [EOF]", causes)
	}
}

func TestYozhCausesOfAPlainMessageIsEmpty(t *testing.T) {
	if causes := errors.New("plain").YozhCauses(); len(causes) != 0 {
		t.Fatalf("causes = %v, want none", causes)
	}
}
