FROM alpine:edge AS core

RUN apk update
RUN apk upgrade
RUN apk add --update go=1.16.5-r0 gcc g++ vips vips-dev

WORKDIR /bitclout/src/core

COPY third_party third_party
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY clouthash clouthash
COPY cmd       cmd
COPY lib       lib
COPY test_data test_data
COPY migrate   migrate
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/core main.go

ENTRYPOINT ["go", "test", "-v", "github.com/bitclout/core/lib"]
