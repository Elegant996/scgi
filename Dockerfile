FROM golang:1.24-alpine AS builder

COPY . ./

# Download dependencies
RUN go mod download

# Build the application
RUN go build -o dist/main .

# Build a small image
FROM scratch

COPY --from=builder /dist/main /

# Command to run
ENTRYPOINT ["/main"]