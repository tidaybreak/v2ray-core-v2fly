package conf

import (
	"encoding/json"
	"github.com/v2fly/v2ray-core/v4/app/server"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"net/url"
	"strings"
)

type StringList []string

type Address struct {
	net.Address
}

type AuthServerConfig struct {
	Type            string
	AuthUrl         *url.URL
	AuthExpire      int32
	TrafficInterval int32
	TrafficUrl      *url.URL
	Address         *Address
	InboundTag      *StringList
	Port            uint16
}

func (c *AuthServerConfig) Build() (*server.AuthServer, error) {
	if c.Type == "" {
		return nil, newError("AccountServer address is not specified.")
	}

	authServer := &server.AuthServer{
		Type:            c.Type,
		AuthUrl:         c.AuthUrl.String(),
		AuthExpire:      c.AuthExpire,
		TrafficInterval: c.TrafficInterval,
		TrafficUrl:      c.TrafficUrl.String(),
		Address: &net.Endpoint{
			Network: net.Network_TCP,
			//Address: c.Address.Build(),
			Port: uint32(c.Port),
		},
	}

	if c.InboundTag != nil {
		for _, s := range *c.InboundTag {
			authServer.InboundTag = append(authServer.InboundTag, s)
		}
	}

	return authServer, nil
}

func (c *AuthServerConfig) UnmarshalJSON(data []byte) error {
	/*if url, err := url.Parse(strings.Trim(string(data[:]), "\"")); err == nil {
		c.Url = url
		return nil
	}
	*/

	var advanced struct {
		Type            string      `json:"type"`
		InboundTag      *StringList `json:"inboundTag"`
		AuthUrl         string      `json:"authUrl"`
		TrafficUrl      string      `json:"trafficUrl"`
		AuthExpire      int32       `json:"authExpire"`
		TrafficInterval int32       `json:"trafficInterval"`
		Address         *Address    `json:"address"`
		Port            uint16      `json:"port"`
	}
	if err := json.Unmarshal(data, &advanced); err == nil {
		c.Type = advanced.Type
		if url, err := url.Parse(strings.Trim(advanced.AuthUrl, "\"")); err == nil {
			c.AuthUrl = url
		}
		if url, err := url.Parse(strings.Trim(advanced.TrafficUrl, "\"")); err == nil {
			c.TrafficUrl = url
		}
		c.AuthExpire = advanced.AuthExpire
		c.TrafficInterval = advanced.TrafficInterval
		c.InboundTag = advanced.InboundTag
		c.Address = advanced.Address
		c.Port = advanced.Port
		return nil
	}

	return newError("failed to parse name server: ", string(data))
}

type Account struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

func (v *Account) Build() *server.Account {
	return &server.Account{
		Username: v.Username,
		Password: v.Password,
	}
}

// ServerConfig is a JSON serializable object for account.Config.
type ServerConfig struct {
	Servers    []*AuthServerConfig `json:"servers"`
	Accounts   []*Account          `json:"accounts"`
	Tag        string              `json:"tag"`
	ApiUser    string              `json:"apiUser"`
	ApiTraffic string              `json:"apiTraffic"`
	SsId       int32               `json:"ssId"`
	TagId      map[string]int32    `json:"tagId"`
	TagVmessId map[string]int32    `json:"tagVmessId"`
	Interval   int32               `json:"interval"`
}

// Build implements Buildable
func (c *ServerConfig) Build() (*server.Config, error) {
	config := &server.Config{
		Tag:        c.Tag,
		ApiUser:    c.ApiUser,
		ApiTraffic: c.ApiTraffic,
		TagId:      c.TagId,
		TagVmessId: c.TagVmessId,
		SsId:       c.SsId,
		Interval:   c.Interval,
	}

	for _, server := range c.Servers {
		ns, err := server.Build()
		if err != nil {
			return nil, newError("failed to build name server").Base(err)
		}
		config.AuthServer = append(config.AuthServer, ns)
	}

	if len(c.Accounts) > 0 {
		config.Accounts = make(map[string]string)
		for _, account := range c.Accounts {
			config.Accounts[account.Username] = account.Password
		}
	}

	return config, nil
}
