
.PHONY: build

gobuild:
	CGO_ENABLED=0 GOOS="linux" GOARCH="amd64" \
		go build \
		-ldflags="-s -w" \
		-tags timetzdata \
		-v \
		-o build/app \
		./cmd/cert-exporter

dockerbuild: 
	docker build -t esinio/traefik-cert-exporter:latest --no-cache .

dokcerpush: dockerbuild
	docker push esinio/traefik-cert-exporter:latest

dockerrun:
	docker run -itd \
    --restart=always \
    --name=traefik-cert-exporter \
    -v /srv/container/traefik/acme.json:/acme.json  \
    -v /etc/traefik/certs:/certs  \
    -v /var/run/docker.sock:/var/run/docker.sock \
    esinio/traefik-cert-exporter

 