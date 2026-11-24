package ssh

import (
	"context"

	gossh "golang.org/x/crypto/ssh"
)

// presenceConn guards each newly issued exchange, including method values kept
// from an exported client. It does not close the transport or existing channels.
// Embedding preserves Conn's metadata, Wait and Close ownership contracts.
type presenceConn struct {
	gossh.Conn
	cfg Config
}

func (c *presenceConn) OpenChannel(kind string, data []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	if err := checkProviderPresence(context.Background(), c.cfg); err != nil {
		return nil, nil, err
	}
	channel, requests, err := c.Conn.OpenChannel(kind, data)
	if err != nil {
		return nil, nil, err
	}
	return &presenceChannel{Channel: channel, cfg: c.cfg}, requests, nil
}

type presenceChannel struct {
	gossh.Channel
	cfg Config
}

// Session.Start/Run can be delayed after NewSession has opened its channel.
// Fence new remote work at its exec/shell/subsystem request as well; data on an
// already-started channel and its completion/close remain unrestricted.
func (c *presenceChannel) SendRequest(name string, reply bool, data []byte) (bool, error) {
	switch name {
	case "exec", "shell", "subsystem":
		if err := checkProviderPresence(context.Background(), c.cfg); err != nil {
			return false, err
		}
	}
	return c.Channel.SendRequest(name, reply, data)
}

func (c *presenceConn) SendRequest(name string, reply bool, data []byte) (bool, []byte, error) {
	if err := checkProviderPresence(context.Background(), c.cfg); err != nil {
		return false, nil, err
	}
	return c.Conn.SendRequest(name, reply, data)
}
