package hwcipher

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

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
	op        int
	cbuf      afAlgCmsg
	mutex     sync.Mutex
}

func NewAfAlg(c *AfAlgConfig) (*AfAlg, error) {
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
	defer syscall.Close(sfd)

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
		return nil, syscall.Errno(errno)
	}

	op := unix.ALG_OP_ENCRYPT
	if c.Decrypt {
		op = unix.ALG_OP_DECRYPT
	}

	a := &AfAlg{
		op:        op,
		cbuf:      afAlgCmsg{}.setOp(op).setIv(c.IV),
		fd:        int(fd),
		blockSize: c.BlockSize,
	}

	runtime.SetFinalizer(a, func(a *AfAlg) {
		syscall.Close(a.fd)
	})

	return a, nil
}

func (a *AfAlg) SetIV(iv []byte) {
	if len(iv) != a.blockSize {
		panic(fmt.Errorf("hwcipher: wrong IV length %d", len(iv)))
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.cbuf = afAlgCmsg{}.setOp(a.op).setIv(iv)
}

func (a *AfAlg) SetKey(key []byte) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := unix.SetsockoptString(a.fd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key))
	if err != nil {
		panic(err)
	}
}

func (a *AfAlg) SetDecrypt(decrypt bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	op := unix.ALG_OP_ENCRYPT
	if decrypt {
		op = unix.ALG_OP_DECRYPT
	}

	a.op = op
	a.cbuf = afAlgCmsg{}.setOp(op)
}

func (a *AfAlg) BlockSize() int {
	return a.blockSize
}

func (a *AfAlg) SafeCryptBlocks(dst, src []byte) error {
	if len(src)%a.blockSize != 0 {
		return errors.New("hwcipher: input not full blocks")
	}

	if len(dst) < len(src) {
		return errors.New("hwcipher: mismatched buffer lengths")
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := syscall.Sendmsg(a.fd, src, a.cbuf, nil, unix.MSG_MORE)
	if err != nil {
		return err
	}
	a.cbuf = nil

	n, _, _, _, err := syscall.Recvmsg(a.fd, dst, nil, 0)
	if err != nil {
		return err
	}
	if n != len(src) {
		return errors.New("read error")
	}
	return nil
}

func (a *AfAlg) CryptBlocks(dst, src []byte) {
	err := a.SafeCryptBlocks(dst, src)
	if err != nil {
		panic(err)
	}
}
