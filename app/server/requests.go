package server

import (
	"bytes"
	"encoding/json"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"net/http"
	"time"
)

type UserConfig struct {
	UserId           int    `json:"user_id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	Ppwd             string `json:"ppwd"`
	UUID             string `json:"uuid"`
	AlterId          uint32 `json:"alter_id"`
	Level            uint32 `json:"level"`
	SSPort           uint32 `json:"ss_port"`
	SSPwd            string `json:"ss_pwd"`
	SSMeth           string `json:"ss_meth"`
	LimitMaxUp       int64  `json:"utm"`
	LimitMaxDown     int64  `json:"dtm"`
	TrafficTotalUp   int64  `json:"ut"`
	TrafficTotalDown int64  `json:"dt"`
	LimitSession     uint32 `json:"ls"`
	LimitSpeedUp     uint32 `json:"lsu"`
	LimitSpeedDown   uint32 `json:"lsd"`
	Tag              string `json:"tag"`
	Enable           bool   `json:"enable"`
}

type UserTraffic struct {
	UserId          int   `json:"user_id"`
	DownloadTraffic int64 `json:"dt"`
	UploadTraffic   int64 `json:"ut"`
}

type syncReq struct {
	UserTraffics []*UserTraffic `json:"user_traffics"`
}

type infoReq struct {
	Total    int              `json:"total"`
	LastTime int64            `json:"last_time"`
	TagIds   map[string]int32 `json:"tag_id"`
}

type syncResp struct {
	Configs   []*UserConfig
	VmessTags []string `json:"vmess_tags"`
}

type authRequest struct {
	UserName string `json:"id"`
	start    time.Time
}

type authResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func parseAuthResponse(payload []byte) (*authResponse, error) {
	userResponse := &authResponse{}
	err := json.Unmarshal(payload, &userResponse)
	if err != nil {
		return nil, errors.New("Unmarshal error")
	}
	return userResponse, nil
}

type trafficRequest struct {
	Uid            int      `json:"uid"`
	TrafficIncUp   int64    `json:"ut"`
	TrafficIncDown int64    `json:"dt"`
	TcpConnNum     int      `json:"tcn"`
	Ips            []string `json:"ips"`
}

type trafficResqonse struct {
	UserName         string `json:"id"`
	LimitMaxUp       int64  `json:"utm"`
	LimitMaxDown     int64  `json:"dtm"`
	TrafficTotalUp   int64  `json:"ut"`
	TrafficTotalDown int64  `json:"dt"`
}

func parseTrafficResponse(payload []byte) ([]*trafficResqonse, error) {
	userTraffic := make([]*trafficResqonse, 0)
	err := json.Unmarshal(payload, &userTraffic)
	if err != nil {
		return nil, errors.New("Unmarshal error")
	}
	return userTraffic, nil
}

func getJson(c *http.Client, url string, target interface{}) error {
	r, err := c.Get(url)
	if err != nil {
		return err
	}
	if r != nil {
		defer r.Body.Close()
		return json.NewDecoder(r.Body).Decode(target)
	}
	return nil
}

func postJson(c *http.Client, url string, dataStruct interface{}, result interface{}) error {
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(dataStruct)
	r, err := http.Post(url, "application/json", buf)
	if r != nil {
		defer r.Body.Close()
		if result != nil {
			return json.NewDecoder(r.Body).Decode(result)
		}
	}
	return err
}
