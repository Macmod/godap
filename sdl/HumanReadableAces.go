package sdl

type ACESList struct {
	SamAccountName string
	Type           string
	RawMask        int
	Mask           []string
	Scope          string
	Inheritance    bool
	Severity       int
}
