FROM golang:1.17-alpine AS build-env
ENV SRCPATH $GOPATH/src/github.com/form3tech-oss/vault-plugin-secrets-grafanacloud
COPY ./ $SRCPATH
WORKDIR $SRCPATH
RUN apk update; \
    apk add --virtual build-dependencies build-base gcc wget git
RUN go test ./... && \
    go install github.com/form3tech-oss/vault-plugin-secrets-grafanacloud/cmd/vault-plugin-secrets-grafanacloud

FROM alpine
COPY --from=build-env /go/bin/vault-plugin-secrets-grafanacloud /var/lib/vault_plugins/
VOLUME /var/lib/vault_plugins
CMD ["/bin/true"]