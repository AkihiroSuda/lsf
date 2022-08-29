package alignutil

func Up(x, align int) int {
	return (x + (align - 1)) & -align
}
