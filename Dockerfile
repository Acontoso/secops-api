FROM --platform=$BUILDPLATFORM golang:1.25.14-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS builder

ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY code/go.mod code/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify

COPY code/ ./
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -tags=lambda.norpc -trimpath -ldflags="-s -w" -o /out/bootstrap .

FROM scratch AS http
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chmod=0555 /out/bootstrap /bootstrap
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/bootstrap"]

FROM public.ecr.aws/lambda/provided:al2023.2026.11.20.02@sha256:35c709c73084df1afa66f7bd46a0be6b95db9da27fa93bd7e45b10701d7e4964 AS lambda
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chmod=0555 /out/bootstrap /var/task/bootstrap
USER 10001:10001
ENTRYPOINT ["/var/task/bootstrap"]
CMD []
