package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("timestamp", cmdTimestamp, `
usage: tuf timestamp [--expires=<days> --manager=<type>]

Update the timestamp manifest.

Options:
  --expires=<days>   Set the timestamp manifest to expire <days> days from now.
`)
}

func cmdTimestamp(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.TimestampWithExpires(expires)
	}
	return repo.Timestamp()
}
