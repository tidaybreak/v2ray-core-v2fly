//go:build !confonly
// +build !confonly

package server

import (
	"context"
	"fmt"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/features/stats"
	feature_stats "github.com/v2fly/v2ray-core/v4/features/stats"
	"strconv"
	"sync"
	"time"
)

type TraCounter struct {
	id int32
	// 当前流量（从启动算起）
	counterUp   stats.Counter
	counterDown stats.Counter

	// 上一次
	trafficLastUp   int64
	trafficLastDown int64
}

type UserInfo struct {
	username   string
	password   string
	authExpire time.Time

	SSPort uint32
	SSPwd  string
	SSMeth string

	// 总已使用流量
	trafficTotalUp   int64
	trafficTotalDown int64
	// 限总流量
	limitMaxUp   int64
	limitMaxDown int64
	// 限速
	limitSpeedUp   uint32
	limitSpeedDown uint32
	// 限Session
	limitSession uint32

	// 出口tag
	OutTag string

	// 当前：流量记录
	lCounter sync.RWMutex
	counter  map[int32]*TraCounter

	// 当前：session记录
	sync.RWMutex
	ips   []string
	conns map[string]int32

	UserId          int
	Email           string
	Ppwd            string
	UUID            string
	AlterId         uint32
	Level           uint32
	Enable          bool
	UploadTraffic   int64
	DownloadTraffic int64
}

func NewUserInfo(config *UserConfig) *UserInfo {
	return &UserInfo{
		UserId:           config.UserId,
		Email:            config.Email,
		Ppwd:             config.Ppwd,
		UUID:             config.UUID,
		Level:            config.Level,
		Enable:           config.Enable,
		AlterId:          config.AlterId,
		SSPort:           config.SSPort,
		SSPwd:            config.SSPwd,
		SSMeth:           config.SSMeth,
		limitMaxUp:       config.LimitMaxUp,
		limitMaxDown:     config.LimitMaxDown,
		limitSpeedUp:     config.LimitSpeedUp,
		limitSpeedDown:   config.LimitSpeedDown,
		limitSession:     config.LimitSession,
		trafficTotalUp:   config.TrafficTotalUp,
		trafficTotalDown: config.TrafficTotalDown,
		OutTag:           config.Tag,
		counter:          make(map[int32]*TraCounter),
		conns:            make(map[string]int32),
	}
}

func (u *UserInfo) setEnable(enable bool) {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	u.Enable = enable
}

func (u *UserInfo) getEnable() bool {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	return u.Enable
}

func (u *UserInfo) isEnableLimitSession() bool {
	if u.limitSession <= 0 {
		return false
	}
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	return uint32(len(u.conns)) >= u.limitSession
}

func (u *UserInfo) setUUID(uuid string) {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	u.UUID = uuid
}

func (u *UserInfo) setSS(config *UserConfig) {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	u.SSPort = config.SSPort
	u.SSPwd = config.SSPwd
	u.SSMeth = config.SSMeth
}

func (u *UserInfo) updateUser(config *UserConfig) {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()
	u.Ppwd = config.Ppwd
	u.Email = config.Email
	u.limitMaxUp = config.LimitMaxUp
	u.limitMaxDown = config.LimitMaxDown
	u.trafficTotalUp = config.TrafficTotalUp
	u.trafficTotalDown = config.TrafficTotalDown
	u.limitSession = config.LimitSession
	u.limitSpeedUp = config.LimitSpeedUp
	u.limitSpeedDown = config.LimitSpeedDown
	u.OutTag = config.Tag
}

func (u *UserInfo) UpdateCounter(inboundTag string, tagId int32, stats feature_stats.Manager) error {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()

	if _, found := u.counter[tagId]; found {
		return nil
	} else {
		ukey := "inbound>>>" + inboundTag + "user>>>" + u.Email + ">>>traffic>>>uplink"
		dkey := "inbound>>>" + inboundTag + "user>>>" + u.Email + ">>>traffic>>>downlink"
		uc, err1 := feature_stats.GetOrRegisterCounter(stats, ukey)
		dc, err2 := feature_stats.GetOrRegisterCounter(stats, dkey)
		if err1 == nil && err2 == nil {
			u.counter[tagId] = &TraCounter{
				counterUp:   uc,
				counterDown: dc,
			}
			return nil
		}
	}
	return nil
}

func (u *UserInfo) GetTraffic(trafficReq map[int32][]trafficRequest) {
	u.lCounter.Lock()
	defer u.lCounter.Unlock()

	//trafficReq := make(map[int32][]trafficRequest, 0)
	for nodeId, counter := range u.counter {
		traffic := trafficRequest{
			Uid: u.UserId,
		}

		if counter.counterUp != nil && counter.trafficLastUp != counter.counterUp.Value() {
			traffic.TrafficIncUp = counter.counterUp.Value() - counter.trafficLastUp
			counter.trafficLastUp = counter.counterUp.Value()
		}
		if counter.counterDown != nil && counter.trafficLastDown != counter.counterDown.Value() {
			traffic.TrafficIncDown = counter.counterDown.Value() - counter.trafficLastDown
			counter.trafficLastDown = counter.counterDown.Value()
		}

		if traffic.TrafficIncUp > 0 || traffic.TrafficIncDown > 0 {
			if _, found := trafficReq[nodeId]; !found {
				trafficReq[nodeId] = make([]trafficRequest, 0)
			}

			traffic.Ips = make([]string, 0)
			mIps := make(map[string]int)
			for _, ip := range u.ips {
				mIps[ip] = 0
			}
			for ip, _ := range mIps {
				traffic.Ips = append(traffic.Ips, ip)
			}
			traffic.TcpConnNum = len(u.conns)

			trafficReq[nodeId] = append(trafficReq[nodeId], traffic)
		}
	}
	//return trafficReq
}

func (u *UserInfo) NewConn(remStr string) {
	u.Lock()
	if len(u.ips) > 10 {
		u.ips = u.ips[1:len(u.ips)]
	}
	u.ips = append(u.ips, remStr)
	_, found := u.conns[remStr]
	if found {
		newError("rebind conn user:", u.Email).AtError().WriteToLog()
		u.conns[remStr] += 1
	} else {
		u.conns[remStr] = 1
	}

	u.Unlock()
}

func (u *UserInfo) CloseConn(remStr string) {
	u.Lock()
	_, found := u.conns[remStr]
	if found {
		delete(u.conns, remStr)
	} else {
		newError("unbind conn fail user:", u.Email).AtDebug().WriteToLog()
	}
	u.Unlock()
}

func (u *UserInfo) PrintConn() {
	u.Lock()
	newError(len(u.conns), " ", u.Email, " ===================================================").AtDebug().WriteToLog()
	str := "\n"
	for k, v := range u.conns {
		str += k + "=" + strconv.Itoa(int(v)) + "\r\n"
	}
	newError(str).AtDebug().WriteToLog()

	u.Unlock()
}

// UserPool user pool
type UserPool struct {
	access sync.RWMutex
	users  map[string]*UserInfo
}

// CreateUser get create user
func (up *UserPool) CreateUser(config *UserConfig) (*UserInfo, error) {
	up.access.Lock()
	defer up.access.Unlock()

	if user, found := up.users[config.Email]; found {
		return user, errors.New(fmt.Sprintf("UserId: %d Already Exists Email: %s", user.UserId, user.Email))
	} else {
		user := NewUserInfo(config)
		up.users[user.Email] = user
		return user, nil
	}
}

// GetTotal
func (up *UserPool) GetTotal() int {
	up.access.Lock()
	defer up.access.Unlock()

	return len(up.users)
}

// GetAllUsers GetAllUsers
func (up *UserPool) GetAllUsers() []*UserInfo {
	up.access.Lock()
	defer up.access.Unlock()

	users := make([]*UserInfo, 0, len(up.users))
	for _, user := range up.users {
		users = append(users, user)
	}
	return users
}

// GetUserByEmail get user by email
func (up *UserPool) GetUserByEmail(email string) (*UserInfo, error) {
	up.access.Lock()
	defer up.access.Unlock()

	if user, found := up.users[email]; found {
		return user, nil
	} else {
		return nil, errors.New(fmt.Sprintf("User Not Found Email: %s", email))
	}
}

// RemoveUserByEmail get user by email
func (up *UserPool) RemoveUserByEmail(email string) {
	up.access.Lock()
	defer up.access.Unlock()
	delete(up.users, email)
}

// NewUserPool New UserPool
func NewUserPool() *UserPool {
	// map key : email
	return &UserPool{
		users: make(map[string]*UserInfo),
	}
}

// Client is the interface for DNS client.
type Client interface {
	// Name of the Client.
	Name() string

	GetUser(ctx context.Context, username string) (*UserInfo, error)

	GetUserBase(username string) *UserInfo
}

var (
	errUserNotFound = errors.New("user not found")
	errUserExpFound = errors.New("user auth expire found")
)
