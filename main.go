package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/PeronGH/iping/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := cmd.NewRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
