//go:build !confonly
// +build !confonly

package server

//go:generate errorgen

import (
	"context"
	"fmt"
	"github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/app/proxyman"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/common/uuid"
	"github.com/v2fly/v2ray-core/v4/features"
	feature_inbound "github.com/v2fly/v2ray-core/v4/features/inbound"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/features/server"
	feature_stats "github.com/v2fly/v2ray-core/v4/features/stats"
	"github.com/v2fly/v2ray-core/v4/proxy"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Server is a AUTH rely server.
type Handler struct {
	sync.Mutex
	policy                policy.Manager
	users                 map[string]*UserInfo
	clients               map[string]Client
	tag                   string
	apiUrl                string
	apiTraffic            string
	stats                 feature_stats.Manager
	inboundHandlerManager feature_inbound.Manager
	syncTask              *task.Periodic
	userPool              *UserPool
	tagId                 map[string]int32
	tagVmessId            map[string]int32
	ssNodeId              int32
	LastTime              int64
	coreInstance          *core.Instance
}

func generateRandomTag() string {
	id := uuid.New()
	return "v2ray.system." + id.String()
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return d.Init(ctx, config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// New creates a new AUTH server with given configuration.
func (d *Handler) Init(ctx context.Context, config *Config, pm policy.Manager) error {
	d.policy = pm
	v := core.MustFromContext(ctx)

	d.clients = make(map[string]Client)
	d.users = make(map[string]*UserInfo)
	d.inboundHandlerManager = v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	d.userPool = NewUserPool()
	d.tag = config.Tag
	d.apiUrl = config.ApiUser
	d.apiTraffic = config.ApiTraffic
	d.tagId = config.TagId
	d.tagVmessId = config.TagVmessId
	d.ssNodeId = config.SsId
	d.LastTime = 0
	d.coreInstance = core.MustFromContext(ctx)

	core.RequireFeatures(ctx, func(sm feature_stats.Manager) {
		d.stats = sm
	})
	if d.tag == "" {
		d.tag = generateRandomTag()
	}

	if len(config.AuthServer) > 0 {
		features.PrintDeprecatedFeatureWarning("simple Account server")
		for _, authServer := range config.AuthServer {
			if authServer.Type == "http" || authServer.Type == "socks" {
				authUrl, err := url.Parse(authServer.AuthUrl)
				if err != nil {
					log.Fatalln(newError("Account config error").Base(err))
				}
				trafficUrl, err := url.Parse(authServer.TrafficUrl)
				if err != nil {
					log.Fatalln(newError("Account config error").Base(err))
				}
				auth := NewHttpAuthServer(authUrl, trafficUrl, authServer.AuthExpire, authServer.TrafficInterval)
				for _, inboundTag := range authServer.InboundTag {
					d.clients[inboundTag] = auth
				}
			}
		}
	}

	for user, pwd := range config.Accounts {
		userInfo := &UserInfo{
			username: user,
			password: pwd,
		}
		d.users[user] = userInfo
	}

	d.syncTask = &task.Periodic{
		Interval: time.Second * time.Duration(config.Interval),
		Execute:  d.SyncTask,
	}

	common.Must(d.syncTask.Start())
	return nil
}

// Type implements common.HasType.
func (*Handler) Type() interface{} {
	return server.ClientType()
}

// Start implements common.Runnable.
func (s *Handler) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Handler) Close() error {
	return nil
}

func (s *Handler) SyncTask() error {
	// 跳过第一次，刚启动是inboundHandlerManager空，导致vmess add user失败
	if s.LastTime == 0 {
		s.LastTime = 1
		return nil
	}

	s.UpdateUser()

	s.UpdateTraffic()

	return nil
}

// AddInboundUser add user to inbound by tag
func (s *Handler) AddVmessUser(user *UserInfo) error {
	if user.UUID == "" {
		return nil
	}

	for tag, _ := range s.tagVmessId {
		h, err := s.inboundHandlerManager.GetHandler(nil, tag)
		if err != nil {
			return newError("can not find handler")
		}
		gi, ok := h.(proxy.GetInbound)
		if !ok {
			return newError("can't get inbound proxy from handler.")
		}
		p := gi.GetInbound()

		um, ok := p.(proxy.UserManager)
		if !ok {
			return newError("proxy is not a UserManager")
		}
		va := &vmess.Account{
			Id:               user.UUID,
			AlterId:          user.AlterId,
			SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AUTO},
		}
		acc, err := va.AsAccount()
		if err != nil {
			return newError("vmessAccount is not a Account")
		}
		u := &protocol.MemoryUser{
			Account: acc,
			Email:   user.Email,
			Level:   0,
		}
		err = um.AddUser(nil, u)

		if err != nil {
			newError("Fail Add User To Vmess Email:", user.Email, "  Tag: ", tag).AtError().WriteToLog()
		} else {
			newError("Success Add User To Vmess Email:", user.Email, "  Tag: ", tag).AtInfo().WriteToLog()
		}
	}
	return nil
}

// RemoveVmessUser RemoveInboundUser remove user from inbound by tag
func (s *Handler) RemoveVmessUser(user *UserInfo) error {
	for tag, _ := range s.tagVmessId {
		h, err := s.inboundHandlerManager.GetHandler(nil, tag)
		if err != nil {
			return newError("can not find handler")
		}
		gi, ok := h.(proxy.GetInbound)
		if !ok {
			return newError("can't get inbound proxy from handler.")
		}
		p := gi.GetInbound()

		um, ok := p.(proxy.UserManager)
		if !ok {
			return newError("proxy is not a UserManager")
		}
		err = um.RemoveUser(nil, user.Email)

		if err != nil {
			newError("Fail Remove User From Vmess Email:", user.Email, " Tag: ", tag).AtError().WriteToLog()
		} else {
			newError("Success Remove User From Vmess Email:", user.Email, " Tag: ", tag).AtInfo().WriteToLog()
		}
	}
	return nil
}

func (s *Handler) AddSSInboundHandler(cfg *UserConfig) error {
	if cfg.SSPwd == "" || cfg.SSPort == 0 || cfg.SSMeth == "" {
		return nil
	}
	CipherType := shadowsocks.CipherType_UNKNOWN
	switch cfg.SSMeth {
	case "aes-128-gcm":
		CipherType = shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		CipherType = shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305":
		CipherType = shadowsocks.CipherType_CHACHA20_POLY1305
	default:
		return nil
	}

	account := serial.ToTypedMessage(&shadowsocks.Account{
		Password:   cfg.SSPwd,
		CipherType: CipherType,
		//Ota:        shadowsocks.Account_Auto,
	})
	inbound := []*core.InboundHandlerConfig{
		{
			Tag: "ss-" + strconv.Itoa(cfg.UserId),
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortRange: net.SinglePortRange(net.Port(cfg.SSPort)),
				Listen:    net.NewIPOrDomain(net.AnyIP),
			}),
			ProxySettings: serial.ToTypedMessage(&shadowsocks.ServerConfig{
				User: &protocol.User{
					Account: account,
					Level:   0,
					Email:   cfg.Email,
				},
				Network: []net.Network{net.Network_TCP, net.Network_UDP},
			}),
		},
	}
	err := core.AddInboundHandler(s.coreInstance, inbound[0])
	if err != nil {
		newError("fail add ss handler: ", cfg.Email, " err:", err.Error()).AtError().WriteToLog()
	} else {
		newError("success add ss handler: ", cfg.Email).AtInfo().WriteToLog()
	}
	return err
}

func (s *Handler) RemoveInboundHandler(cfg *UserConfig) error {
	inboundManager := s.coreInstance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	err := inboundManager.RemoveHandler(context.Background(), "ss-"+strconv.Itoa(cfg.UserId))
	if err != nil {
		newError("fail remove ss handler: ", cfg.Email, " err:", err.Error()).AtError().WriteToLog()
	} else {
		newError("success remove ss handler: ", cfg.Email).AtInfo().WriteToLog()
	}
	return err
}

func (s *Handler) UpdateUser() error {
	for Tag, _ := range s.tagVmessId {
		_, err := s.inboundHandlerManager.GetHandler(nil, Tag)
		if err != nil {
			newError("can not find vmess tag:", Tag).AtError().WriteToLog()
		}
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp := syncResp{}
	req := infoReq{
		Total:    s.userPool.GetTotal(),
		LastTime: s.LastTime,
		TagIds:   s.tagId,
	}
	LastTime := time.Now().Unix()
	err := postJson(httpClient, s.apiUrl, &req, &resp)
	if err != nil {
		newError("API连接失败,请检查API地址 当前地址: ", s.apiUrl, " 错误信息:", err.Error()).AtError().WriteToLog()
		return nil
	}

	for _, cfg := range resp.Configs {
		if cfg.Email == "" {
			continue
		}

		user, _ := s.userPool.GetUserByEmail(cfg.Email)
		if user == nil {
			newUser, err := s.userPool.CreateUser(cfg)
			if err != nil {
				newError("fail create user: ", err.Error()).AtError().WriteToLog()
			}
			if newUser.Enable {
				if s.tagVmessId != nil {
					s.AddVmessUser(newUser)
				}
				if s.ssNodeId > 0 {
					s.AddSSInboundHandler(cfg)
				}
			}
		} else {
			user.updateUser(cfg)

			if user.Enable != cfg.Enable {
				newError("user:", user.Email, " change able old: ", user.Enable, " new:", cfg.Enable).AtInfo().WriteToLog()
				user.setEnable(cfg.Enable)
				if !user.Enable {
					s.RemoveVmessUser(user)
					s.RemoveInboundHandler(cfg)
				} else {
					s.AddVmessUser(user)
					s.AddSSInboundHandler(cfg)
				}
			}

			if user.UUID != cfg.UUID {
				newError("user:", user.Email, " change uuid old: ", cfg.UUID, " new:", cfg.UUID).AtInfo().WriteToLog()
				s.RemoveVmessUser(user)
				user.setUUID(cfg.UUID)
				s.AddVmessUser(user)
			}

			if user.SSPwd != cfg.SSPwd || user.SSPort != cfg.SSPort || user.SSMeth != cfg.SSMeth {
				newError("user:", user.Email, " change ss info old: ", cfg.SSMeth, " new:", cfg.SSMeth).AtInfo().WriteToLog()
				s.RemoveInboundHandler(cfg)
				user.setSS(cfg)
				if user.SSPort > 0 {
					s.AddSSInboundHandler(cfg)
				}
			}
		}
	}

	if s.userPool.GetTotal() > 0 {
		s.LastTime = LastTime
	}
	return nil
}

func (s *Handler) UpdateTraffic() error {
	trafficReq := make(map[int32][]trafficRequest, 0)
	for _, tagId := range s.tagId {
		trafficReq[tagId] = make([]trafficRequest, 0)
	}
	for _, tagId := range s.tagVmessId {
		trafficReq[tagId] = make([]trafficRequest, 0)
	}
	trafficReq[s.ssNodeId] = make([]trafficRequest, 0)

	for _, user := range s.userPool.GetAllUsers() {
		user.GetTraffic(trafficReq)
		//user.PrintConn()
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}
	err := postJson(httpClient, s.apiTraffic, &trafficReq, nil)
	if err != nil {
		newError("failed to post traffic req").Base(err).AtError().WriteToLog()
	} else {
		newError("trafficReq:", trafficReq).AtDebug().WriteToLog()
	}

	return nil
}

func (s *Handler) BindConn(tagInbound, protocol, username string, conn internet.Connection) error {
	if tagInbound == "" {
		return nil
	}

	addr := conn.RemoteAddr().Network() + ":" + conn.RemoteAddr().String()
	userInfo, _ := s.userPool.GetUserByEmail(username)
	if userInfo == nil {
		// 本地认证时
		return nil
	}

	userInfo.NewConn(addr)
	switch protocol {
	case "socks":
		{
			userInfo.UpdateCounter(tagInbound, s.tagId[tagInbound], s.stats)
		}
	case "http":
		{
			userInfo.UpdateCounter(tagInbound, s.tagId[tagInbound], s.stats)
		}
	case "ss":
		{
			userInfo.UpdateCounter(tagInbound, s.ssNodeId, s.stats)
		}
	case "vmess":
		{
			userInfo.UpdateCounter(tagInbound, s.tagVmessId[tagInbound], s.stats)
		}
	}

	//client, found := s.clients[tagInbound]
	//if !found {
	//	return nil
	//}
	//
	//userInfo = client.GetUserBase(username)
	//if userInfo != nil {
	//	userInfo.NewConn(addr)
	//}

	return nil
}

func (s *Handler) CloseConn(tagInbound, username string, addr string) error {
	if tagInbound == "" {
		return nil
	}

	userInfo, _ := s.userPool.GetUserByEmail(username)
	if userInfo != nil {
		userInfo.CloseConn(addr)
		return nil
	} else {
		return nil
	}

	client, found := s.clients[tagInbound]
	if !found {
		return nil
	}

	userInfo = client.GetUserBase(username)
	if userInfo != nil {
		userInfo.CloseConn(addr)
	}
	return nil
}

func (s *Handler) Permission(inboundTag, username string) (string, uint32, uint32, error) {
	userInfo, _ := s.userPool.GetUserByEmail(username)
	if userInfo == nil {
		//p := s.policy.ForLevel(cfgLevel;)
		//if p.Buffer.Rate != 0 {
		//
		//}
		return "", 0, 0, nil
	}

	if !userInfo.getEnable() {
		return "", 0, 0, errors.New(fmt.Sprintf("server disable maybe limit max traffic user:%s", username))
	}

	if userInfo.isEnableLimitSession() {
		return "", 0, 0, errors.New(fmt.Sprintf("limit max session user:%s", username))
	}

	return userInfo.OutTag, userInfo.limitSpeedUp, userInfo.limitSpeedDown, nil
}

// LookupIP implements dns.Client.
func (s *Handler) CheckNormal(inboundTag, username, password string) error {
	if _, found := s.tagId[inboundTag]; !found {
		return errors.New("null user")
	}

	if username == "" || password == "" {
		return errors.New("auth get nil username or password")
	}

	userInfo, _ := s.userPool.GetUserByEmail(username)

	if userInfo == nil {
		return errors.New("can not find userinfo:", username, " pass:", password)
	}

	if userInfo.Ppwd != password {
		return errors.New("password wrong user:", username, " pass:", password)
	}
	return nil
	//return s.TrafficLimit(inboundTag, s.tagId[inboundTag], userInfo)
}

func (s *Handler) CheckVmess(inboundTag, email string, conn internet.Connection) (int, error) {
	if _, found := s.tagVmessId[inboundTag]; !found {
		return 0, nil
	}

	userInfo, _ := s.userPool.GetUserByEmail(email)

	if userInfo == nil {
		return 407, errors.New("can not find email:", email)
	}

	return 0, nil
	//return s.TrafficLimit(inboundTag, s.tagVmessId[inboundTag], userInfo)
}

func (s *Handler) CheckSS(inboundTag, email string, conn internet.Connection) (int, error) {
	if s.ssNodeId == 0 {
		return 0, nil
	}

	userInfo, _ := s.userPool.GetUserByEmail(email)
	if userInfo == nil {
		return 407, errors.New("can not find email:", email)
	}

	return 0, nil
	//return s.TrafficLimit(inboundTag, s.ssNodeId, userInfo)
}
