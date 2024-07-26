export PATH=$PATH:/home/ti/dev_data/go1.17/bin
export GOROOT=/home/ti/dev_data/go1.17
export GOPATH=/data/ofidc/gopath

cd /home/ti/code/v2ray-core-v2fly/main
env CGO_ENABLED=0 go build -o ../v2ray -ldflags "-s -w"
env CGO_ENABLED=0 go build -o /home/data/docker-volume/v2ray/bin/v2ray -ldflags "-s -w"

cd /home/ti/code/v2fly.org/v2ray-core/infra/control/main
env CGO_ENABLED=0 go build -o /tmp/v2ctl -tags confonly -ldflags "-s -w"
env CGO_ENABLED=0 go build -o ../../../v2ctl -tags confonly -ldflags "-s -w"
env CGO_ENABLED=0 go build -o /home/data/docker-volume/v2ray/bin/v2ctl -tags confonly -ldflags "-s -w"


env CGO_ENABLED=0 go build -o /tmp/v2ctl -tags confonly -ldflags "-s -w"
scp -P 62738 /root/v2ray 183.61.119.41:/usr/bin/v2ray


cd /data/ofidc/project/v2ray.com/core/main
env CGO_ENABLED=0 go build -o /data/test/bin/v2ray -ldflags "-s -w"


# protoc
cd /home/ti/code/v2ray-core-v2fly
/home/ti/code/v2ray-core-v2fly/protoc/bin/protoc --proto_path=/home/ti/code/v2ray-core-v2fly --go_out=/tmp /home/ti/code/v2ray-core-v2fly/app/policy/config.proto
/home/ti/code/v2ray-core-v2fly/protoc/bin/protoc --proto_path=/home/ti/code/v2ray-core-v2fly --go_out=/tmp /home/ti/code/v2ray-core-v2fly/common/protocol/user.proto
/home/ti/code/v2ray-core-v2fly/protoc/bin/protoc --proto_path=/home/ti/code/v2ray-core-v2fly --go_out=/tmp /home/ti/code/v2ray-core-v2fly/app/server/config.proto
/home/ti/code/v2ray-core-v2fly/protoc/bin/protoc --proto_path=/home/ti/code/v2ray-core-v2fly --go_out=/tmp /home/ti/code/v2ray-core-v2fly/app/policy/config.proto



docker stop v2ray
docker rm v2ray

docker run -d \
--name v2ray \
--privileged     \
--restart always     \
--net mynet     \
--ip 172.18.0.125 \
--mount type=bind,source=/data/ofidc/docker-volume/v2ray/config.json,target=/etc/v2ray/config.json \
--mount type=bind,source=/data/ofidc/docker-volume/v2ray/logs,target=/var/log/v2ray \
--mount type=bind,source=/data/ofidc/docker-volume/v2ray/bin,target=/usr/bin/v2ray \
--mount type=bind,source=/etc/resolv.docker.conf,target=/etc/resolv.conf \
v2ray/official


sniffing  开启sniffing.destOverride.http|tls 会用8.8.8.8来解析，可能解析出来ip不能访问，myip.ipip.net出现过这问题
http会覆盖变量，配置无效http/server.go:285
socks5 有效
vmess 有效

inbounds socks：
{
    "port": 87,  // SOCKS 代理端口，在浏览器中需配置代理并指向这个端口
    "listen": "0.0.0.0",
    "protocol": "socks",
    "settings": {
        "udp": true,
        "auth": "password", // 匿名：noauth
        "accounts": [
            {
            "user": "ofidc",
            "pass": "ofidc999"
            }
        ]
    }
}

inbounds http：
{
    "listen": "0.0.0.0",
    "port": 88,
    "protocol": "http",
    "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
    },
    "settings": {
        "auth": "password", // 匿名：noauth
        "accounts": [
            {
            "user": "ofidc",
            "pass": "ofidc999"
            }
        ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
            "header": {
                "type": "none"
            }
        }
    }
}



outbounds shadowsocks：
{
    "protocol": "shadowsocks",
    "tag": "huanshi",
    "settings": {
            "servers": [{
                    "address": "23.91.100.158",
                    "method": "aes-256-gcm",
                    "ota": false,
                    "password": "testpwd",
                    "port": 2728
            }]
    }
}

outbounds vmess：
{
    "protocol": "vmess",
    "settings": {
        "vnext": [{
            "address": "172.18.0.10", // 服务器地址，请修改为你自己的服务器 ip 或域名
            "port": 1092,  // 服务器端口
            "users": [{ "id": "5105fe80-bbbc-48d2-b662-ec858489d3d9","alterId": 0 }]
        }]
    }
}