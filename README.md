# Vote Decrypt

> [!CAUTION]
> This service was never used in production. We changed the concept.

Vote Decrypt is a service to decrypt a list of encrypted votes and return then
in random order.

The service is only reachable via gPRC.


## Install and run

### From Source

To install the service from source, download the repository and call

```
go build
./vote-decrypt
```


### With Docker

The container needs a key file. As default, it looks for it at
`/run/secrets/vote_main_key` inside the container. Another file (from inside the
container) can be choosen via the first argument. The file has to be mounted
inside the docker container.

```
docker run -v "$(pwd)"/main_key:/run/secrets/vote_main_key vote-decrypt
```


## Main Key File

The service needs a main key. This has to be 32 random bytes. It is used to sign
the poll keys and to sign the voting result.

The main file can be created with

```
head /dev/urandom -c 32 > main.key
```

or with the vote-decrypt tool

```
vote-decrypt main-key KEYFILE
```


## Public Key

The users need the public key of the main key to make sure the data from the
vote-decrypt service was not altered with.

The public key can be created with:

```
vote-decrypt pub-key KEYFILE
```

The keys are in raw bytes. To decode it with base64 use

```
vote-decrypt pub-key KEYFILE --base64
```


## Help

To see the options for all commands of vote-decrypt, call:

```
vote-decrypt --help
```


## Storage

`vote-decrypt` saves some data for each started poll. Currently the only
supported storrage backend is the filesystem.

As default, the uses the folder `vote_data`. 

When a poll is started, a `.key`-file is created. It contains the private poll
key for the started key. KEEP THIS PRIVATE. This file is needed to decrypt the
poll after it is done. If this file gets lost, it is not possible to decrypt a
poll.

When a poll is stopped, a `.hash`-file is created. It contains the signature for
the poll result. The file makes sure, that stop can not be called with different
data.


## gRPC interface

The service can be reached via [gRPC](https://grpc.io/). The proto file can be
found in the folder
[grpc/decrypt.proto](https://github.com/OpenSlides/vote-decrypt/blob/main/grpc/decrypt.proto).

It contains three methods. `PublicMainKey`, `Start`, `Stop`, and `Clean`.


### PublicMainKey

PublicMainKey returns the public main key that is used to sign the poll poll
keys and the poll results.


### Start

Start has to be called at the beginning of a poll. It tells the vote-decrypt
server to start accepting votes.

The method returns the public poll key and its signature. The signature can be
validated with the public main key.


### Stop

Stop has to be called to finish the poll. It expects a list of votes. 

The method call be called multiple times, but only with the same payload. It is
not possible to call it with different votes.

The method returns the decrypted votes as one blob of data and it signature. The
signature can be validated with the public main key.


### Clear

Clear should be called after stop to remove all poll related data.


## Poll Workflow

A poll with vote-decrypt has three parties. The clients, the poll manager and
vote-decrypt:

1.  The clients have to receive the public main key via a secure channel.
2.  The poll manager start a poll by calling `Start`.
3.  The poll manager distributes the public poll key with its signature to the
    clients.
4.  The clients validate the public poll key with its signature and the main
    key.
5.  The clients create there vote and encrypt them with the public poll key.
6.  The clients send the encrypted votes to the poll manager.
7.  After the poll manager received all votes, he sends them to vote-decrypt by
    calling the `Stop`method.
8.  The poll manager receives the decrypted vote list with its signature and
    distributes them to the clients as a blob.
9.  The clients validate the vote blob with its signature and the main key.
10. The clients evaulute the poll.

To evalute the vote blob, the clients make sure that there value are in the blob
and where therefore respected. The signed blob contains a poll-id that the
client use to make sure, that the blob is for the correct poll.


## Configuration

### Environment Variables

The service uses the following enironment variables:

* `VOTE_DECRYPT_PORT`: Port for the gRPC serice to listen to. Default is `9014`.
* `VOTE_DECRYPT_STORE`: Folder to store the poll keys. Default is `vote_data`.


## TODOs:

* Fix the Stop method to hash the input instead of the output.
* Fix more timing attacks.
* Write a postgres storage backend.
* Write errors messages as output.
* Use the main key to encrypt the stored data (poll keys and poll hashes)
