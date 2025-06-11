package libterm

type NotATerminalError struct{}

func (e NotATerminalError) Error() string {
	return "not a terminal"
}
