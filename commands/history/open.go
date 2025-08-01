package history

import (
	"context"
	"fmt"

	"github.com/docker/buildx/util/cobrautil/completion"
	"github.com/docker/buildx/util/desktop"
	"github.com/docker/cli/cli/command"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type openOptions struct {
	builder string
	ref     string
}

func runOpen(ctx context.Context, dockerCli command.Cli, opts openOptions) error {
	nodes, err := loadNodes(ctx, dockerCli, opts.builder)
	if err != nil {
		return err
	}

	recs, err := queryRecords(ctx, opts.ref, nodes, nil)
	if err != nil {
		return err
	}

	if len(recs) == 0 {
		if opts.ref == "" {
			return errors.New("no records found")
		}
		return errors.Errorf("no record found for ref %q", opts.ref)
	}

	rec := &recs[0]

	url := desktop.BuildURL(fmt.Sprintf("%s/%s/%s", rec.node.Builder, rec.node.Name, rec.Ref))
	return browser.OpenURL(url)
}

func openCmd(dockerCli command.Cli, rootOpts RootOptions) *cobra.Command {
	var options openOptions

	cmd := &cobra.Command{
		Use:   "open [OPTIONS] [REF]",
		Short: "Open a build record in Docker Desktop",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				options.ref = args[0]
			}
			options.builder = *rootOpts.Builder
			return runOpen(cmd.Context(), dockerCli, options)
		},
		ValidArgsFunction: completion.Disable,
	}

	return cmd
}
