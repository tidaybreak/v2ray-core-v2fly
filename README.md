export PATH=$PATH:/home/ti/dev_data/go1.17/bin
export GOROOT=/home/ti/dev_data/go1.17
export GOPATH=/data/ofidc/gopath

cd /home/ti/code/v2fly.org/v2ray-core/main
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
cd /home/ti/project/v2ray.com/core
/home/ti/project/v2ray.com/core/protoc/bin/protoc --proto_path=/home/ti/project/v2ray.com/core --go_out=../../ /home/ti/project/v2ray.com/core/app/policy/config.proto
/home/ti/project/v2ray.com/core/protoc/bin/protoc --proto_path=/home/ti/project/v2ray.com/core --go_out=../../ /home/ti/project/v2ray.com/core/app/server/config.proto
/home/ti/project/v2ray.com/core/protoc/bin/protoc --proto_path=/home/ti/project/v2ray.com/core --go_out=../../ /home/ti/project/v2ray.com/core/common/protocol/user.proto



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
