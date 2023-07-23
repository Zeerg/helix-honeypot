# Building Stage
FROM golang:alpine as build

RUN mkdir /app
WORKDIR /app
COPY . ./
WORKDIR /app/cmd
RUN go get ./... && go build -o /helix-honeypot

#Final Stage
FROM alpine:latest
WORKDIR /
COPY --from=build /helix-honeypot /helix-honeypot

ENTRYPOINT ["/helix-honeypot"]