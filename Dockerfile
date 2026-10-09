FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /voice-enroll ./cmd/voice-enroll

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /voice-enroll /voice-enroll
USER nonroot:nonroot
ENTRYPOINT ["/voice-enroll"]
