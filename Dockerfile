FROM golang:1.16-alpine as builder

WORKDIR /app
COPY . .
RUN go build && \
      chmod 777 banking-service

FROM alpine:latest
WORKDIR /root/
COPY app.env .
COPY --from=builder /app/banking-service .
CMD [ "./banking-service" ]