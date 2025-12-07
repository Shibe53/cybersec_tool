FROM alpine:latest

RUN apk add --no-cache curl

COPY victim_login.sh /victim_login.sh
RUN chmod +x /victim_login.sh

CMD ["sh", "/victim_login.sh"]
