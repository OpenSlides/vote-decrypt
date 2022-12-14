package decrypt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/OpenSlides/vote-decrypt/decrypt"
	"github.com/OpenSlides/vote-decrypt/errorcode"
)

// TODO: test concurency.

func TestStart(t *testing.T) {
	cr := cryptoMock{}
	store := NewStoreMock()
	d := decrypt.New(cr, store)

	t.Run("first call", func(t *testing.T) {
		pubKey, pubKeySig, err := d.Start(context.Background(), "test/1")
		if err != nil {
			t.Fatalf("start returned: %v", err)
		}

		if string(pubKey) != "pollPubKey" {
			t.Errorf("start returned `%v`, expected `pollPubKey`", pubKey)
		}

		if string(pubKeySig) != "pollKeySig" {
			t.Errorf("start returned `%v`, expected `pollKeySig`", pubKeySig)
		}
	})

	t.Run("second call", func(t *testing.T) {
		pubKey, pubKeySig, err := d.Start(context.Background(), "test/1")
		if err != nil {
			t.Fatalf("start returned: %v", err)
		}

		if string(pubKey) != "pollPubKey" {
			t.Errorf("start returned `%s`, expected `pollPubKey`", pubKey)
		}

		if string(pubKeySig) != "pollKeySig" {
			t.Errorf("start returned `%s`, expected `pollKeySig`", pubKeySig)
		}

	})
}

func TestStop(t *testing.T) {
	cr := cryptoMock{}

	t.Run("valid", func(t *testing.T) {
		store := NewStoreMock()
		d := decrypt.New(cr, store, decrypt.WithRandomSource(randomMock{}))

		if _, _, err := d.Start(context.Background(), "test/1"); err != nil {
			t.Fatalf("start: %v", err)
		}

		votes := [][]byte{
			[]byte(`enc:"Y"`),
			[]byte(`enc:"N"`),
			[]byte(`enc:"A"`),
		}

		content, signature, err := d.Stop(context.Background(), "test/1", votes)
		if err != nil {
			t.Errorf("stop: %v", err)
		}

		if string(signature) != "sig:"+string(content) {
			t.Errorf("got signature %s, expected signature %s", signature, "sig:"+string(content))
		}

		expected := `{"id":"test/1","votes":["Y","A","N"]}`
		if string(content) != expected {
			t.Errorf("got %s, expected %s", content, expected)
		}
	})

	t.Run("decrypt error", func(t *testing.T) {
		store := NewStoreMock()
		d := decrypt.New(cr, store, decrypt.WithRandomSource(randomMock{}))

		if _, _, err := d.Start(context.Background(), "test/1"); err != nil {
			t.Fatalf("start: %v", err)
		}

		votes := [][]byte{
			[]byte(`enc:"Y"`),
			[]byte(`encwrong:"N"`),
			[]byte(`enc:"A"`),
		}

		content, signature, err := d.Stop(context.Background(), "test/1", votes)
		if err != nil {
			t.Errorf("stop: %v", err)
		}

		if string(signature) != "sig:"+string(content) {
			t.Errorf("got signature %s, expected signature %s", signature, "sig:"+string(content))
		}

		expected := `{"id":"test/1","votes":["Y","A",{"error":"encryption not valid"}]}`
		if string(content) != expected {
			t.Errorf("got %s, expected %s", content, expected)
		}
	})

	t.Run("Not started", func(t *testing.T) {
		store := NewStoreMock()
		d := decrypt.New(cr, store, decrypt.WithRandomSource(randomMock{}))

		votes := [][]byte{
			[]byte(`enc:"Y"`),
			[]byte(`enc:"N"`),
			[]byte(`enc:"A"`),
		}

		_, _, err := d.Stop(context.Background(), "test/1", votes)
		if !errors.Is(err, errorcode.NotExist) {
			t.Errorf("stop returned `%v` expected `%v`", err, errorcode.NotExist)
		}
	})

	t.Run("To many votes", func(t *testing.T) {
		store := NewStoreMock()
		d := decrypt.New(
			cr,
			store,
			decrypt.WithRandomSource(randomMock{}),
			decrypt.WithMaxVotes(2),
		)

		if _, _, err := d.Start(context.Background(), "test/1"); err != nil {
			t.Fatalf("start: %v", err)
		}

		votes := [][]byte{
			[]byte(`enc:"Y"`),
			[]byte(`enc:"N"`),
			[]byte(`enc:"A"`),
		}

		_, _, err := d.Stop(context.Background(), "test/1", votes)
		if !errors.Is(err, errorcode.Invalid) {
			t.Errorf("stop returned `%v` expected `%v`", err, errorcode.Invalid)
		}
	})

	t.Run("Other content format", func(t *testing.T) {
		listToContent := func(id string, decrypted [][]byte) ([]byte, error) {
			return bytes.Join(decrypted, []byte(",")), nil
		}

		store := NewStoreMock()
		d := decrypt.New(
			cr,
			store,
			decrypt.WithRandomSource(randomMock{}),
			decrypt.WithListToContent(listToContent),
		)

		if _, _, err := d.Start(context.Background(), "test/1"); err != nil {
			t.Fatalf("start: %v", err)
		}

		votes := [][]byte{
			[]byte(`enc:"Y"`),
			[]byte(`enc:"N"`),
			[]byte(`enc:"A"`),
		}

		content, signature, err := d.Stop(context.Background(), "test/1", votes)
		if err != nil {
			t.Errorf("stop: %v", err)
		}

		if string(signature) != "sig:"+string(content) {
			t.Errorf("got signature %s, expected signature %s", signature, "sig:"+string(content))
		}

		expected := `"Y","A","N"`
		if string(content) != expected {
			t.Errorf("got %s, expected %s", content, expected)
		}
	})
}

func TestClear(t *testing.T) {
	cr := cryptoMock{}
	store := NewStoreMock()
	d := decrypt.New(cr, store)

	if err := d.Clear(context.Background(), "test/1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
}
