package freebsd

// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/sys/elf_common.h#L949
const (
	AT_NULL         = 0
	AT_IGNORE       = 1
	AT_EXECFD       = 2
	AT_PHDR         = 3
	AT_PHENT        = 4
	AT_PHNUM        = 5
	AT_PAGESZ       = 6
	AT_BASE         = 7
	AT_FLAGS        = 8
	AT_ENTRY        = 9
	AT_NOTELF       = 10
	AT_UID          = 11
	AT_EUID         = 12
	AT_GID          = 13
	AT_EGID         = 14
	AT_EXECPATH     = 15
	AT_CANARY       = 16
	AT_CANARYLEN    = 17
	AT_OSRELDATE    = 18
	AT_NCPUS        = 19
	AT_PAGESIZES    = 20
	AT_PAGESIZESLEN = 21
	AT_TIMEKEEP     = 22
	AT_STACKPROT    = 23
	AT_EHDRFLAGS    = 24
	AT_HWCAP        = 25
	AT_HWCAP2       = 26
	AT_BSDFLAGS     = 27
	AT_ARGC         = 28
	AT_ARGV         = 29
	AT_ENVC         = 30
	AT_ENVV         = 31
	AT_PS_STRINGS   = 32
	AT_FXRNG        = 33
	AT_KPRELOAD     = 34
	AT_COUNT        = 35
)
