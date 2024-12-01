FROM golang:1.23-alpine3.20 AS build
WORKDIR /app
COPY . .
RUN env CGO_ENABLED=0 GOBIN=/build go install .

FROM scratch
COPY --from=build /build/* /
ENTRYPOINT ["/ndpresponder"]
