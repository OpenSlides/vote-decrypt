package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/OpenSlides/vote-decrypt/store/postgres"
	"github.com/ory/dockertest/v3"
)

func startPostgres(t *testing.T) (string, func()) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	runOpts := dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "13",
		Env: []string{
			"POSTGRES_USER=postgres",
			"POSTGRES_PASSWORD=password",
			"POSTGRES_DB=database",
		},
	}

	resource, err := pool.RunWithOptions(&runOpts)
	if err != nil {
		t.Fatalf("Could not start postgres container: %s", err)
	}

	return resource.GetPort("5432/tcp"), func() {
		if err = pool.Purge(resource); err != nil {
			t.Fatalf("Could not purge postgres container: %s", err)
		}
	}
}

func TestPostgres(t *testing.T) {
	ctx := context.Background()
	port, close := startPostgres(t)
	defer close()

	addr := fmt.Sprintf(`user=postgres password='password' host=localhost port=%s dbname=database`, port)
	p, err := postgres.New(ctx, addr)
	if err != nil {
		t.Fatalf("Creating postgres backend returned: %v", err)
	}
	defer p.Close()

	t.Logf("Postgres port: %s", port)

	t.Run("SaveKey", func(t *testing.T) {
		t.Run("Saving key twice", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll1", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			err := p.SaveKey(ctx, "poll1", []byte("other key in same poll"))

			if err == nil {
				t.Errorf("saveKey called on the same id did not return an error.")
			}
		})
	})

	t.Run("LoadKey", func(t *testing.T) {
		t.Run("load existing poll", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll2", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			got, err := p.LoadKey(ctx, "poll2")
			if err != nil {
				t.Fatalf("LoadKey: %v", err)
			}

			if string(got) != "my-key" {
				t.Errorf("got key %v, expected %v", got, "my-key")
			}
		})

		t.Run("load unknown poll", func(t *testing.T) {
			_, err := p.LoadKey(ctx, "unknown")
			if err == nil {
				t.Errorf("expect an error")
			}
		})
	})

	t.Run("ValidateSignature", func(t *testing.T) {
		t.Run("save signature", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll3", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			if err := p.ValidateSignature(ctx, "poll3", []byte("my-hash")); err != nil {
				t.Fatalf("ValidateSignature: %v", err)
			}
		})

		t.Run("save signature twice", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll4", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			if err := p.ValidateSignature(ctx, "poll4", []byte("my-hash")); err != nil {
				t.Fatalf("ValidateSignature: %v", err)
			}

			if err := p.ValidateSignature(ctx, "poll4", []byte("my-hash")); err != nil {
				t.Fatalf("ValidateSignature: %v", err)
			}
		})

		t.Run("save different signature", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll5", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			if err := p.ValidateSignature(ctx, "poll5", []byte("my-hash")); err != nil {
				t.Fatalf("ValidateSignature: %v", err)
			}

			err := p.ValidateSignature(ctx, "poll5", []byte("WRONG"))
			if err == nil {
				t.Errorf("ValidateSignature for a different sigature did not return an error")
			}
		})
	})

	t.Run("ClearPoll", func(t *testing.T) {
		t.Run("Saving key twice with clear in between", func(t *testing.T) {
			if err := p.SaveKey(ctx, "poll6", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

			if err := p.ClearPoll(ctx, "poll6"); err != nil {
				t.Fatalf("ClearPoll: %v", err)
			}

			if err := p.SaveKey(ctx, "poll6", []byte("my-key")); err != nil {
				t.Fatalf("SaveKey: %v", err)
			}

		})
	})

}
