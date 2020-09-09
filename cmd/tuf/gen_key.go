package main

import (
	"fmt"

	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/data"
)

func init() {
	register("gen-key", cmdGenKey, `
usage: tuf gen-key [--type=<type> --expires=<days>] <role>

Generate a new signing key for the given role.

The key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root manifest will also be staged
with the addition of the key's ID to the role's list of key IDs.

Options:
  --expires=<days>   Set the root manifest to expire <days> days from now.
  --type=<type>      Chooses one of key types. The default is ed25519, alternative is ecdsa-sha2-nistp256
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var id string
	var err error
	var keyType string
	if keyType = args.String["--type"]; keyType == "" {
		keyType = data.KeyTypeEd25519
	}
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		id, err = repo.GenKeyWithTypeAndExpires(role, keyType, expires)
	} else {
		id, err = repo.GenKeyWithType(role, keyType)
	}
	if err != nil {
		return err
	}
	fmt.Println("Generated", role, "key with ID", id)
	return nil
}
