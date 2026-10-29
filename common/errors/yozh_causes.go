package errors

// YozhCauses returns the errors this error carries in its message rather than as its inner error.
// retry.On reports a failed retry as New(attempts).Base(ErrRetryFailed): the attempts — the dial
// errors among them — are in the message, and Unwrap leads only to ErrRetryFailed. The message is
// not exported, so whoever needs the attempts asks here.
func (err *Error) YozhCauses() []error {
	var causes []error
	for _, part := range err.message {
		switch v := part.(type) {
		case []error:
			causes = append(causes, v...)
		case error:
			causes = append(causes, v)
		}
	}
	return causes
}
