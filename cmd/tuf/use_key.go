package main

import (
	"fmt"
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("use-key", cmdUseKey, `
usage: tuf use-key --manager=<type> --external-key-id=<id> <role>

Imports key of given key-id from given manager.
Currently this is applicable to KMS only.

For KMS, a key of given ARN identifier will be referenced in kms.json file in kms directory.

The root manifest will be staged with the addition of the key's ID to the role's list of key IDs.

Options:
  --expires=<days>       Set the root manifest to expire <days> days from now.
  --manager=<type>       Chooses one of key manager. Options are: local and kms. The default is local.
  --external-key-id=<id> Identifier specific to the manager of keys. For KMS this is ARN of the key.
`)
}

func cmdUseKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var ids []string
	var err error
	var externalKeyId string

	if externalKeyId = args.String["--external-key-id"]; externalKeyId == "" {
		return fmt.Errorf("missing external key ID, specify --external-key-id")
	}

	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		ids, err = repo.ImportKeyWithExpires(externalKeyId, role, expires)
	} else {
		ids, err = repo.ImportKey(externalKeyId, role)
	}
	if err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Printf("Key with ID %s (external key ID %s) is now used for role %s\n", id, externalKeyId, role)
	}
	return nil
}
