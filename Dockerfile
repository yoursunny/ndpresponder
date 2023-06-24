FROM golang:1.20-bookworm AS build
WORKDIR /app
COPY . .
RUN env GOBIN=/build go install .

FROM debian:bookworm
COPY --from=build /build/* /
ENTRYPOINT ["/ndpresponder"]
