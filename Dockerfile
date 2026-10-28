FROM golang:1.27-alpine3.24 AS build
WORKDIR /app
COPY . .
RUN env CGO_ENABLED=0 GOBIN=/build go install .

FROM scratch
COPY --from=build /build/* /
ENTRYPOINT ["/ndpresponder"]
