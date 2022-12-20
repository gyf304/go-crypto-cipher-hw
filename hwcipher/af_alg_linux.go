package hwcipher

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const MAX_IV_LENGTH = 32

type AfAlgConfig struct {
	AlgType   string
	AlgName   string
	BlockSize int
	Key       []byte
	IV        []byte
	Decrypt   bool
}

type AfAlg struct {
	fd        int
	blockSize int
	mutex     sync.Mutex
}

type afAlgIV struct {
	ivlen uint32
	iv    [MAX_IV_LENGTH]byte
}

func cmsgData(cmsg *syscall.Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(syscall.SizeofCmsghdr))
}

func NewAfAlg(c *AfAlgConfig) (*AfAlg, error) {
	if len(c.IV) > MAX_IV_LENGTH {
		return nil, fmt.Errorf("IV length %d is too long", len(c.IV))
	}

	if c.BlockSize == 0 {
		if len(c.IV) == 0 {
			c.BlockSize = len(c.Key)
		} else {
			c.BlockSize = len(c.IV)
		}
	}

	sfd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}

	addr := &unix.SockaddrALG{
		Type: c.AlgType,
		Name: c.AlgName,
	}

	err = unix.Bind(sfd, addr)
	if err != nil {
		return nil, err
	}

	// set key
	err = unix.SetsockoptString(sfd, unix.SOL_ALG, unix.ALG_SET_KEY, string(c.Key))
	if err != nil {
		return nil, err
	}

	fd, _, errno := unix.Syscall(unix.SYS_ACCEPT, uintptr(sfd), 0, 0)
	if errno != 0 {
		syscall.Close(sfd)
		return nil, syscall.Errno(errno)
	}

	err = syscall.Close(sfd)
	if err != nil {
		return nil, err
	}

	a := &AfAlg{
		fd:        int(fd),
		blockSize: c.BlockSize,
	}

	runtime.SetFinalizer(a, func(a *AfAlg) {
		syscall.Close(a.fd)
	})

	// set op, iv
	cbuf := make([]byte, syscall.CmsgSpace(4)+syscall.CmsgSpace(20))
	opCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	opCmsgHdr.Level = unix.SOL_ALG
	opCmsgHdr.Type = unix.ALG_SET_OP
	opCmsgHdr.SetLen(syscall.CmsgLen(4))
	opPtr := (*uint32)(cmsgData(opCmsgHdr))
	if c.Decrypt {
		*opPtr = unix.ALG_OP_DECRYPT
	} else {
		*opPtr = unix.ALG_OP_ENCRYPT
	}
	ivCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[syscall.CmsgSpace(4)]))
	ivCmsgHdr.Level = unix.SOL_ALG
	ivCmsgHdr.Type = unix.ALG_SET_IV
	ivCmsgHdr.SetLen(syscall.CmsgLen(20))
	iv := (*afAlgIV)(cmsgData(ivCmsgHdr))
	iv.ivlen = uint32(len(c.IV))
	copy(iv.iv[:], c.IV)

	err = syscall.Sendmsg(int(fd), nil, cbuf, nil, unix.MSG_MORE)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *AfAlg) BlockSize() int {
	return a.blockSize
}

func (a *AfAlg) CryptBlocks(dst, src []byte) {
	if len(src)%a.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("crypto/cipher: mismatched buffer lengths")
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := unix.Sendmsg(a.fd, src, nil, nil, unix.MSG_MORE)
	if err != nil {
		panic(err)
	}

	n, err := unix.Read(a.fd, dst[:len(src)])
	if err != nil {
		fmt.Println("read error", err)
		panic(err)
	}
	if n != len(dst) {
		panic("read error")
	}
}