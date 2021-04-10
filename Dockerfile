FROM golang:1.16.3-buster AS build
WORKDIR /go/src/app
COPY . .
RUN go build .

FROM debian:buster
COPY --from=build /go/src/app/ndpresponder /ndpresponder
ENTRYPOINT ["/ndpresponder"]
