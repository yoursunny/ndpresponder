FROM golang:1.17-bullseye AS build
WORKDIR /app
COPY . .
RUN go build .

FROM debian:bullseye
COPY --from=build /app/ndpresponder /ndpresponder
ENTRYPOINT ["/ndpresponder"]
