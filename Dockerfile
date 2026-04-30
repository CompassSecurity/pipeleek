FROM alpine:3.21

RUN apk --no-cache add ca-certificates

ARG TARGETARCH

COPY pipeleek_${TARGETARCH} /usr/local/bin/pipeleek

RUN chmod +x /usr/local/bin/pipeleek

ENTRYPOINT ["/usr/local/bin/pipeleek"]
