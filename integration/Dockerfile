FROM golang:1.27.2
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/zitadeltg ./cmd/zitadeltg
RUN go test -race -tags=integration -run '^$' ./integration
CMD ["go", "test", "-race", "-tags=integration", "-count=1", "-timeout=12m", "-v", "./integration"]
