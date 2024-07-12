package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/OpenSlides/vote-decrypt/crypto"
	"github.com/OpenSlides/vote-decrypt/decrypt"
	"github.com/OpenSlides/vote-decrypt/grpc"
	"github.com/OpenSlides/vote-decrypt/store/filesystem"
	"github.com/OpenSlides/vote-decrypt/store/postgres"
	"github.com/alecthomas/kong"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel := interruptContext()
	defer cancel()

	cliCtx := kong.Parse(&cli, kong.UsageOnError())

	var err error
	switch cliCtx.Command() {
	case "server <main-key>":
		err = runServer(ctx)

	case "main-key <main-key>":
		err = runMainKey()

	case "pub-key <main-key>":
		err = runPubKey()

	default:
		panic(fmt.Sprintf("Unknown command: %s", cliCtx.Command()))
	}

	if err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

var cli struct {
	Server struct {
		MainKey *os.File `arg:"" help:"Path to the main key file."`

		Port         int    `help:"Port for the server. Defaults to 9014." short:"p" env:"VOTE_DECRYPT_PORT" default:"9014"`
		Store        string `help:"Path for the file system storage of poll keys." env:"VOTE_DECRYPT_STORE" default:"vote_data"`
		PostgresConf string `help:"Config for Postgres" env:"VOTE_DECRYPT_POSTGRES"`
	} `cmd:"" help:"Starts the vote decrypt grpc server." default:"withargs"`

	MainKey struct {
		MainKey string `arg:"" help:"Path to the main key file."`
	} `cmd:"" help:"Creates a main key file. It is just 32 bytes of random data."`

	PubKey struct {
		MainKey     *os.File `arg:"" help:"Path to the main key file."`
		SkipNewline bool     `help:"Do not output the trailing newline." short:"n"`
		Base64      bool     `help:"Decode the output with base64." short:"b" name:"base64"`
	} `cmd:"" help:"Calculates the public key for a private key file"`
}

func runServer(ctx context.Context) error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(cli.Server.MainKey, key); err != nil {
		return fmt.Errorf("reading key: %w", err)
	}

	cryptoLib := crypto.New(key, rand.Reader, nil)

	fmt.Printf("Public Main Key: %s\n", base64.StdEncoding.EncodeToString(cryptoLib.PublicMainKey()))

	var store decrypt.Store
	switch {
	case cli.Server.PostgresConf != "":
		pg, err := postgres.New(ctx, cli.Server.PostgresConf)
		if err != nil {
			return fmt.Errorf("connecting to postgres: %w", err)
		}

		store = pg

	default:
		store = filesystem.New(cli.Server.Store)

	}

	decrypter := decrypt.New(
		cryptoLib,
		store,
	)

	addr := fmt.Sprintf(":%d", cli.Server.Port)

	if err := grpc.RunServer(ctx, decrypter, addr); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	return nil
}

func runPubKey() error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(cli.PubKey.MainKey, key); err != nil {
		return fmt.Errorf("reading key: %w", err)
	}

	pubKey := crypto.New(key, rand.Reader, nil).PublicMainKey()

	decodedKey := string(pubKey)
	if cli.PubKey.Base64 {
		decodedKey = base64.StdEncoding.EncodeToString(pubKey)
	}

	print := fmt.Println
	if cli.PubKey.SkipNewline {
		print = fmt.Print
	}
	print(decodedKey)

	return nil
}

func runMainKey() error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("reading key: %w", err)
	}

	if err := os.WriteFile(cli.MainKey.MainKey, key, 0o600); err != nil {
		return fmt.Errorf("writing main key: %w", err)
	}

	return nil
}

// interruptContext works like signal.NotifyContext. It returns a context that
// is canceled, when a signal is received.
//
// It listens on os.Interrupt and unix.SIGTERM. If the signal is received two
// times, os.Exit(2) is called.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, unix.SIGTERM)
		<-sig
		cancel()
		<-sig
		os.Exit(2)
	}()
	return ctx, cancel
}
