FROM golang:1.17-bullseye AS build
WORKDIR /go/src/app
COPY . .
RUN go build .

FROM debian:bullseye
COPY --from=build /go/src/app/ndpresponder /ndpresponder
ENTRYPOINT ["/ndpresponder"]
