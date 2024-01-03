package fn

// Result is a type alias for Either[T, error]. This is useful as a result type
// that allows all functions to return an single argument, that forces the
// caller to examine the result in order to extract any of the values.
type Result[T any] struct {
	Either[T, error]
}

// Ok returns a Result[T] with the given value.
func Ok[T any](v T) Result[T] {
	return Result[T]{
		Either: NewLeft[T, error](v),
	}
}

// Err returns a Result[T] with the given error.
func Err[T any](err error) Result[T] {
	return Result[T]{
		Either: NewRight[T](err),
	}
}

// IsOk returns true if the result is a value.
func (r Result[T]) IsOk() bool {
	return r.IsLeft()
}

// IsErr returns true if the result is an error.
func (r Result[T]) IsErr() bool {
	return r.IsRight()
}
