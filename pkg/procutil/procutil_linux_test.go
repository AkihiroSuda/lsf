package procutil

import (
	"gotest.tools/v3/assert"
	"testing"
)

func TestHeadAddr(t *testing.T) {
	maps := []byte(`555556aa8000-555556aa9000 rw-p 00000000 00:00 0                          [heap]
7eff537ac000-7eff537b2000 r--p 00000000 08:02 566450                     /home/suda/freebsd/rootfs/libexec/ld-elf.so.1
7eff537b2000-7eff537c9000 r-xp 00005000 08:02 566450                     /home/suda/freebsd/rootfs/libexec/ld-elf.so.1
7eff537c9000-7eff537ca000 rw-p 0001b000 08:02 566450                     /home/suda/freebsd/rootfs/libexec/ld-elf.so.1
7eff537ca000-7eff537cb000 rw-p 0001b000 08:02 566450                     /home/suda/freebsd/rootfs/libexec/ld-elf.so.1
7eff537cb000-7eff537cc000 rw-p 00000000 00:00 0 
7fff59cb2000-7fff59cd3000 rw-p 00000000 00:00 0                          [stack]
7fff59d2d000-7fff59d31000 r--p 00000000 00:00 0                          [vvar]
7fff59d31000-7fff59d33000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
`)
	expected := uintptr(0x7eff537ac000)
	got, err := headAddr(maps)
	assert.NilError(t, err)
	assert.Equal(t, expected, got)
}
