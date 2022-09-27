FROM golang:1.19-bullseye AS build
WORKDIR /app
COPY . .
RUN env GOBIN=/build go install .

FROM debian:bullseye
COPY --from=build /build/* /
ENTRYPOINT ["/ndpresponder"]
