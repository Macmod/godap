package sdl

type HEADER struct {
	Revision    string
	Sbz1        string
	Control     string
	OffsetOwner string
	OffsetGroup string
	OffsetSacl  string
	OffsetDacl  string
}

type ACLHEADER struct {
	ACLRevision  string
	Sbz1         string
	ACLSizeBytes string
	ACECount     string
	Sbz2         string
}

type ACEHEADER struct {
	ACEType      string
	ACEFlags     string
	AceSizeBytes string
}

type ACEMASK struct {
	mask string
}

type ACEFLAGS struct {
	flags string
}
