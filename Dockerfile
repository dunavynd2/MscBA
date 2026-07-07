ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev linux-headers git

COPY go.mod /go-ethereum/
COPY go.sum /go-ethereum/
RUN cd /go-ethereum && go mod download

ADD . /go-ethereum

RUN cd /go-ethereum && go run build/ci.go install -static ./cmd/geth
RUN cd /go-ethereum && go run build/ci.go install -static

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /go-ethereum/build/bin/* /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp

ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""
LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"
