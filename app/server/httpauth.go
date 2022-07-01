//go:build !confonly
// +build !confonly

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/signal/pubsub"
)

type HttpAuthServer struct {
	sync.RWMutex
	users           map[string]*UserInfo
	pub             *pubsub.Service
	trafficUpdate   *task.Periodic
	reqID           uint32
	httpClient      *http.Client
	authURL         string
	authExpire      int32
	TrafficInterval int32
	trafficURL      string
	name            string
}

func NewHttpAuthServer(authUrl, trafficUrl *url.URL, authExpire, trafficInterval int32) *HttpAuthServer {
	s := baseHttpAuthServer(authUrl, trafficUrl, authExpire, trafficInterval)
	tr := &http.Transport{
		IdleConnTimeout: 90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 60,
		Transport: tr,
	}
	common.Must(s.trafficUpdate.Start())

	newError("Account: created http auth client for ", authUrl.String()).AtInfo().WriteToLog()
	return s
}

func baseHttpAuthServer(authUrl, trafficUrl *url.URL, authExpire, trafficInterval int32) *HttpAuthServer {
	s := &HttpAuthServer{
		users:      make(map[string]*UserInfo),
		pub:        pubsub.NewService(),
		name:       "http//" + authUrl.Host,
		authURL:    authUrl.String(),
		authExpire: authExpire,
		trafficURL: trafficUrl.String(),
	}
	s.trafficUpdate = &task.Periodic{
		Interval: time.Second * time.Duration(trafficInterval),
		Execute:  s.TrafficUpdate,
	}
	return s
}

// Name returns client name
func (s *HttpAuthServer) Name() string {
	return s.name
}

func (s *HttpAuthServer) TrafficUpdate() error {
	//s.RLock()
	//trafficReq := make([]trafficRequest, 0)
	//for _, user := range s.users {
	//	traffic := trafficRequest {
	//		Uid: user.UserId,
	//	}
	//	if user.counterUp != nil && user.trafficLastUp != user.counterUp.Value() {
	//		traffic.TrafficIncUp = user.counterUp.Value() - user.trafficLastUp
	//		user.trafficLastUp = user.counterUp.Value()
	//	}
	//	if user.counterDown != nil && user.trafficLastDown != user.counterDown.Value() {
	//		traffic.TrafficIncDown = user.counterDown.Value() - user.trafficLastDown
	//		user.trafficLastDown = user.counterDown.Value()
	//	}
	//	if traffic.TrafficIncUp > 0 || traffic.TrafficIncDown > 0 {
	//		traffic.Ips, traffic.TcpConnNum = user.InfoConn()
	//		trafficReq = append(trafficReq, traffic)
	//	}
	//	//user.PrintConn()
	//}
	//s.RUnlock()
	//
	////if len(trafficReq) > 0 {
	//deadline := time.Now().Add(time.Second * 8)
	//accCtx := context.Background()
	//accCtx, cancel := context.WithDeadline(accCtx, deadline)
	//defer cancel()
	//
	//jsonBody, err := json.Marshal(trafficReq)
	//resp, err := s.jsonPost(accCtx, s.trafficURL, jsonBody)
	//if err != nil {
	//	newError("failed to post traffic req").Base(err).AtError().WriteToLog()
	//} else {
	//	//newError("traffic info update url:", s.trafficURL, " body:", string(jsonBody)).AtDebug().WriteToLog()
	//}
	//
	//userMaxTraffic, err := parseTrafficResponse(resp)
	//if err != nil {
	//	newError("failed to parse traffic res").Base(err).AtError().WriteToLog()
	//}
	//for _, traffic := range userMaxTraffic {
	//	s.updateUserMaxTraffic(traffic.UserName, traffic)
	//}
	////}
	return nil
}

func (s *HttpAuthServer) getUserByExpire(username string) (*UserInfo, error) {
	s.RLock()
	userInfo, found := s.users[username]
	s.RUnlock()

	if !found {
		return nil, errUserNotFound
	}

	now := time.Now()
	if userInfo.authExpire.Before(now) {
		return nil, errUserExpFound
	}

	return userInfo, nil
}

func (s *HttpAuthServer) updateUserAuth(username, password string) {
	s.Lock()

	userInfo, found := s.users[username]
	if !found {
		userInfo = &UserInfo{
			username: username,
			password: password,
			conns:    make(map[string]int32),
		}
		s.users[username] = userInfo
		newError(s.name, "new user auth account info: ", username, " ", password).AtInfo().WriteToLog()
	} else {
		userInfo.password = password
		newError(s.name, "update user auth account info: ", username, " ", password).AtDebug().WriteToLog()
	}

	userInfo.authExpire = time.Now()
	exp, _ := time.ParseDuration(strconv.Itoa(int(s.authExpire)) + "s")
	userInfo.authExpire = userInfo.authExpire.Add(exp)

	s.Unlock()
}

func (s *HttpAuthServer) updateUserMaxTraffic(username string, traffic *trafficResqonse) {
	s.Lock()
	userInfo, found := s.users[username]
	s.Unlock()

	if found {
		userInfo.limitMaxUp = traffic.LimitMaxUp
		userInfo.limitMaxDown = traffic.LimitMaxDown
		if traffic.TrafficTotalUp > 0 {
			userInfo.trafficTotalUp = traffic.TrafficTotalUp
		}
		if traffic.TrafficTotalDown > 0 {
			userInfo.trafficTotalDown = traffic.TrafficTotalDown
		}
	}
}

func (s *HttpAuthServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *HttpAuthServer) sendQuery(ctx context.Context, username string) {
	newError(s.name, " querying: ", username).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 8)
	}

	go func() {
		accCtx := context.Background()
		accCtx, cancel := context.WithDeadline(accCtx, deadline)
		defer cancel()

		req := &authRequest{
			UserName: username,
		}
		jsonBody, err := json.Marshal(req)
		resp, err := s.jsonPost(accCtx, s.authURL, jsonBody)
		if err != nil {
			s.pub.Publish(username, nil)
			newError("failed to retrive response").Base(err).AtError().WriteToLog()
			return
		}
		userResponse, err := parseAuthResponse(resp)
		if err != nil {
			s.pub.Publish(username, nil)
			newError("failed to handle userinfo response").Base(err).AtError().WriteToLog()
			return
		}
		if userResponse.Username != "" && userResponse.Password != "" {
			s.updateUserAuth(userResponse.Username, userResponse.Password)
		}
		s.pub.Publish(username, nil)
	}()
}

func (s *HttpAuthServer) jsonPost(ctx context.Context, url string, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("acc server returned code %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (s *HttpAuthServer) GetUserBase(username string) *UserInfo {
	s.RLock()
	userInfo, _ := s.users[username]
	s.RUnlock()
	return userInfo
}

// GetUser is called from dns.Server->queryIPTimeout
func (s *HttpAuthServer) GetUser(ctx context.Context, username string) (*UserInfo, error) {
	userInfo, err := s.getUserByExpire(username)
	if userInfo != nil {
		//newError(s.name, "auth user cache HIT ", username).Base(err).AtDebug().WriteToLog()
		return userInfo, err
	}

	var sub *pubsub.Subscriber
	sub = s.pub.Subscribe(username)
	defer sub.Close()

	done := make(chan interface{})
	go func() {
		if sub != nil {
			select {
			case <-sub.Wait():
			case <-ctx.Done():
			}
		}
		close(done)
	}()
	s.sendQuery(ctx, username)

	for {
		userInfo, err := s.getUserByExpire(username)
		if userInfo != nil {
			return userInfo, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
	}
}
