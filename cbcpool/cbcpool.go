package cbcpool

import (
	"crypto/cipher"
	"errors"
)

type MutableBlockMode interface {
	cipher.BlockMode
	SetIV([]byte)
	SetKey([]byte)
	SetDecrypt(bool)
}

type Pool struct {
	pool      chan MutableBlockMode
	blockSize int
}

type pooledBlockMode struct {
	pool    *Pool
	iv      []byte
	key     []byte
	decrypt bool
}

func (p *pooledBlockMode) SetIV(iv []byte) {
	if len(iv) != len(p.iv) {
		panic("wrong IV length")
	}
	copy(p.iv, iv)
}

func (p *pooledBlockMode) SetKey(key []byte) {
	if len(key) != len(p.key) {
		panic("wrong key length")
	}
	copy(p.key, key)
}

func (p *pooledBlockMode) SetDecrypt(decrypt bool) {
	p.decrypt = decrypt
}

func (p *pooledBlockMode) CryptBlocks(dst, src []byte) {
	b := <-p.pool.pool
	b.SetDecrypt(p.decrypt)
	b.SetIV(p.iv)
	b.CryptBlocks(dst, src)
	srcLen := len(src)
	var newIV []byte
	if p.decrypt {
		newIV = src[srcLen-p.pool.blockSize : srcLen]
	} else {
		newIV = dst[srcLen-p.pool.blockSize : srcLen]
	}
	p.SetIV(newIV)
	p.pool.pool <- b
}

func (p *pooledBlockMode) BlockSize() int {
	return p.pool.blockSize
}

func NewPool(blockSize int, modes ...cipher.BlockMode) (*Pool, error) {
	if blockSize <= 0 {
		return nil, errors.New("blockSize must be positive")
	}
	pool := &Pool{
		pool:      make(chan MutableBlockMode, len(modes)),
		blockSize: blockSize,
	}
	for _, mode := range modes {
		ivMode, ok := mode.(MutableBlockMode)
		if !ok {
			return nil, errors.New("mode does not support SetIV")
		}
		if ivMode.BlockSize() != blockSize {
			return nil, errors.New("mode has wrong block size")
		}
		pool.pool <- ivMode
	}
	return pool, nil
}

func (p *Pool) Get(key []byte, iv []byte, isRead bool) cipher.BlockMode {
	m := &pooledBlockMode{
		pool: p,
		iv:   make([]byte, p.blockSize),
		key:  make([]byte, len(key)),
	}
	m.SetDecrypt(isRead)
	m.SetIV(iv)
	m.SetKey(key)
	return m
}
