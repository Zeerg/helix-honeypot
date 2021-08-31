# Building Stage
FROM golang:alpine as build

RUN mkdir /app
WORKDIR /app
COPY . ./
RUN go mod download && go build -o /helix-honeypot

FROM alpine:latest
WORKDIR /

# Until Go Embed stuff
COPY --from=build /helix-honeypot /helix-honeypot

EXPOSE 8000

ENTRYPOINT ["/helix-honeypot"]