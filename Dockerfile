# Building Stage
FROM golang:alpine as build

RUN mkdir /app
WORKDIR /app
COPY . ./
RUN go mod download && go build -o /helix-honeypot

#Final Stage
FROM alpine:latest
WORKDIR /
COPY --from=build /helix-honeypot /helix-honeypot
RUN addgroup -S helix && adduser -S helix -G helix

EXPOSE 8000

ENTRYPOINT ["/helix-honeypot"]