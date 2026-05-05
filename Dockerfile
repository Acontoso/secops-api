FROM golang:1.22-alpine AS build_go_stage

RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

WORKDIR /app/server

COPY code/go.mod code/go.sum ./
RUN go mod download && go mod verify

COPY code/ ./
# CGO_ENABLED: Makes go binary statically linked and does not rely on system C libaries, important for docker alpine images
# GOOS: Target OS to build on
# GOARCH: Target CPU architecture to build on
# ldflags "-w -s": Strip debug information to reduce binary size (harder to reverse engineer FF)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bootstrap

# Final runtime image
FROM alpine:3.20

# Create non-root user BEFORE copying files so chown is correct
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

WORKDIR /app

COPY --from=build_go_stage --chown=appuser:appuser /app/server/bootstrap .

USER appuser

EXPOSE 8080

CMD ["./bootstrap"]
