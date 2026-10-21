FROM golang:1.26.10-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -o /migrate ./cmd/migrate
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /server /server
COPY --from=build /migrate /migrate
EXPOSE 8080
ENTRYPOINT ["/server"]
