FROM golang:alpine

WORKDIR /go/src/CS425/CS425-MP2

COPY . .

EXPOSE 8081
ADD . /tmp

RUN go build -o main .

CMD ["./main"]
