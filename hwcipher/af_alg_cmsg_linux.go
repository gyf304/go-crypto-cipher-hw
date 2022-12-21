package hwcipher

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type afAlgCmsg []byte

func cmsgData(cmsg *syscall.Cmsghdr, offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(syscall.SizeofCmsghdr) + uintptr(offset))
}

func (m afAlgCmsg) setOp(op int) afAlgCmsg {
	cbuf := make([]byte, syscall.CmsgSpace(4))
	opCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	opCmsgHdr.Level = unix.SOL_ALG
	opCmsgHdr.Type = unix.ALG_SET_OP
	opCmsgHdr.SetLen(syscall.CmsgLen(4))
	opPtr := (*uint32)(cmsgData(opCmsgHdr, 0))
	*opPtr = uint32(op)
	return append(m, cbuf...)
}

func (m afAlgCmsg) setIv(iv []byte) afAlgCmsg {
	payloadLen := 4 + len(iv)
	cmsgSpace := syscall.CmsgSpace(payloadLen)
	cbuf := make([]byte, cmsgSpace)
	ivCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	ivCmsgHdr.Level = unix.SOL_ALG
	ivCmsgHdr.Type = unix.ALG_SET_IV
	ivCmsgHdr.SetLen(syscall.CmsgLen(payloadLen))
	ivLenPtr := (*uint32)(cmsgData(ivCmsgHdr, 0))
	*ivLenPtr = uint32(len(iv))
	ivPtr := (*[1024]byte)(cmsgData(ivCmsgHdr, 4))
	copy(ivPtr[:len(iv)], iv)
	return append(m, cbuf...)
}
