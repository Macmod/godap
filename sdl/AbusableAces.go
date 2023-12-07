package sdl

type ACESList struct {
	SamAccountName        string
	GENERIC_ALL           bool
	GENERIC_WRITE         bool
	WRITE_OWNER           bool
	WRITE_DACL            bool
	FORCE_CHANGE_PASSWORD bool
	ADD_MEMBER            bool
}
