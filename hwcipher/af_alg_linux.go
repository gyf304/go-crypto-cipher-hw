package hwcipher

import (
	"errors"
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
	decrypt   bool
	mutex     sync.Mutex
}

type afAlgIV struct {
	ivlen uint32
	iv    [MAX_IV_LENGTH]byte
}

func cmsgData(cmsg *syscall.Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(syscall.SizeofCmsghdr))
}

func initFd(fd int, decrypt bool, iv []byte) error {
	afAlgIVSize := (int)(unsafe.Sizeof(afAlgIV{}))

	// set op, iv
	cbuf := make([]byte, syscall.CmsgSpace(4)+syscall.CmsgSpace(afAlgIVSize))
	opCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	opCmsgHdr.Level = unix.SOL_ALG
	opCmsgHdr.Type = unix.ALG_SET_OP
	opCmsgHdr.SetLen(syscall.CmsgLen(4))
	opPtr := (*uint32)(cmsgData(opCmsgHdr))
	if decrypt {
		*opPtr = unix.ALG_OP_DECRYPT
	} else {
		*opPtr = unix.ALG_OP_ENCRYPT
	}
	ivCmsgHdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[syscall.CmsgSpace(4)]))
	ivCmsgHdr.Level = unix.SOL_ALG
	ivCmsgHdr.Type = unix.ALG_SET_IV
	ivCmsgHdr.SetLen(syscall.CmsgLen(afAlgIVSize))
	ivMsg := (*afAlgIV)(cmsgData(ivCmsgHdr))
	ivMsg.ivlen = uint32(len(iv))
	copy(ivMsg.iv[:], iv)

	return syscall.Sendmsg(int(fd), nil, cbuf, nil, unix.MSG_MORE)
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
		decrypt:   c.Decrypt,
		fd:        int(fd),
		blockSize: c.BlockSize,
	}

	runtime.SetFinalizer(a, func(a *AfAlg) {
		syscall.Close(a.fd)
	})

	err = initFd(a.fd, c.Decrypt, c.IV)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *AfAlg) SetIV(iv []byte) {
	if len(iv) != a.blockSize {
		panic(fmt.Errorf("hwcipher: wrong IV length %d", len(iv)))
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := initFd(a.fd, a.decrypt, iv)
	if err != nil {
		panic(err)
	}
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

	err := unix.Sendmsg(a.fd, src, nil, nil, unix.MSG_MORE)
	if err != nil {
		return err
	}

	n, err := unix.Read(a.fd, dst[:len(src)])
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
