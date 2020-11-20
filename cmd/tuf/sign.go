package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("sign", cmdSign, `
usage: tuf sign [--manager=<type>] <manifest>

Sign a manifest.
`)
}

func cmdSign(args *docopt.Args, repo *tuf.Repo) error {
	return repo.Sign(args.String["<manifest>"])
}
