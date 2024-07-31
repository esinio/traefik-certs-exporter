FROM golang:1.22-alpine as builder

ADD . ./src

WORKDIR /go/src

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk --no-cache add ca-certificates upx \
    && go env -w GOPROXY='https://goproxy.cn,direct' \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS="linux" GOARCH="amd64" \
        go build \
        -ldflags="-s -w" \
        -tags timetzdata \
        -v \
        -o /app \
        ./cmd/cert-exporter \
    && upx -9 /app

FROM scratch as production

ENV TZ="Asia/Shanghai"

COPY --from=builder /app /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

CMD ["/app"]