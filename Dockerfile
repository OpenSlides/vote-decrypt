FROM golang:1.22.0-alpine as base
WORKDIR /root/

RUN apk add git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build

# Development build.
FROM base as development

RUN ["go", "install", "github.com/githubnemo/CompileDaemon@latest"]
EXPOSE 9014

CMD CompileDaemon -log-prefix=false -command="./vote-decrypt /run/secrets/vote_main_key"


# Productive build
FROM scratch

LABEL org.opencontainers.image.title="Vote Decrypt"
LABEL org.opencontainers.image.description="Vote Decrypt decryptes a list of votes and returns them in random order."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/OpenSlides/vote-decrypt"

COPY --from=base /root/vote-decrypt .
EXPOSE 9014

ENTRYPOINT ["/vote-decrypt"]
CMD ["server", "/run/secrets/vote_main_key"]
