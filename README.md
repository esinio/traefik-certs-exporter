# acme-export

## target file: /path/acme.json

## destination files:

```
certs/
    example.com/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
    sub.example.nl/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
certs_flat/
    example.com.crt
    example.com.key
    example.com.chain.pem
    sub.example.nl.crt
    sub.example.nl.key
    sub.example.nl.chain.pem
```

# Usage



```shell
podman pull esinio/traefik-cert-exporter
podman run -itd \
    --restart=always \
    --name=traefik-cert-exporter \
    -v /srv/container/traefik/acme/cert.json:/acme.json  \
    -v /etc/traefik/certs:/certs  \
    -v /run/podman/podman.sock:/var/run/docker.sock \
    esinio/traefik-cert-exporter
```

# Add container label
```
"traefik.cert.domain=example.com
```