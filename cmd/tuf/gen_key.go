package main

import (
	"fmt"
	"github.com/theupdateframework/go-tuf/data"
	"time"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("gen-key", cmdGenKey, `
usage: tuf gen-key [--type=<type> --expires=<days> --manager=<type>] <role>

Generate a new signing key for the given role using given key manager.

For local manager, the key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json".

For KMS, a new key will be generated at KMS and referenced in kms.json file in kms directory.

The root manifest will also be staged with the addition of the key's ID to the role's list of key IDs.

Options:
  --expires=<days>   Set the root manifest to expire <days> days from now.
  --manager=<type>   Chooses one of key manager. Options are: local and kms. The default is local.  
  --type=<type>      Chooses one of key types. Options are: ed25519 and ecdsa-sha2-nistp256. The default is ed25519.
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var keyIds []string
	var err error
	var keyType string

	if keyType = args.String["--type"]; keyType == "" {
		keyType = data.KeyTypeEd25519
	}
	if arg := args.String["--expires"]; arg != "" {
		var expires time.Time
		expires, err = parseExpires(arg)
		if err != nil {
			return err
		}
		keyIds, err = repo.GenKeyWithTypeAndExpires(role, keyType, expires)
	} else {
		keyIds, err = repo.GenKeyWithType(role,keyType)
	}
	if err != nil {
		return err
	}
	for _, id := range keyIds {
		fmt.Println("Generated", role, "key with ID", id)
	}
	return nil
}
