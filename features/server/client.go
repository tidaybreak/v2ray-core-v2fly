package server

import (
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/v2fly/v2ray-core/v4/features"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

// Client is a V2Ray feature for querying DNS information.
//
// v2ray:api:stable
type Client interface {
	features.Feature

	CheckNormal(tagInbound, username, password string) error

	CheckVmess(tagInbound, email string, conn internet.Connection) (int, error)

	CheckSS(tagInbound, email string, conn internet.Connection) (int, error)

	BindConn(tagInbound, protocol, username string, conn internet.Connection) error

	CloseConn(tagInbound, username, addr string) error

	Permission(tagInbound, username string) (string, uint32, uint32, error)
}

// ClientType returns the type of Client interface. Can be used for implementing common.HasType.
//
// v2ray:api:beta
func ClientType() interface{} {
	return (*Client)(nil)
}

// ErrEmptyResponse indicates that DNS query succeeded but no answer was returned.
var ErrEmptyResponse = errors.New("empty response")

type RCodeError uint16

func (e RCodeError) Error() string {
	return serial.Concat("rcode: ", uint16(e))
}

func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
