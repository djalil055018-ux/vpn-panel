package nodeadoption

import "golang.org/x/sys/unix"

func makeFIFO(name string) error { return unix.Mkfifo(name, 0600) }
