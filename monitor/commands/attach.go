package commands

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/buildx/monitor/types"
	"github.com/pkg/errors"
)

type AttachCmd struct {
	m types.Monitor

	stdout io.WriteCloser
}

func NewAttachCmd(m types.Monitor, stdout io.WriteCloser) types.Command {
	return &AttachCmd{m, stdout}
}

func (cm *AttachCmd) Info() types.CommandInfo {
	return types.CommandInfo{HelpMessage: "attach to a buildx server or a process in the container"}
}

func (cm *AttachCmd) Exec(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errors.Errorf("server name must be passed")
	}
	ref := args[1]
	var id string

	isProcess, err := isProcessID(ctx, cm.m, ref)
	if err == nil && isProcess {
		cm.m.Attach(ctx, ref)
		id = ref
	}
	if id == "" {
		refs, err := cm.m.List(ctx)
		if err != nil {
			return errors.Errorf("failed to get the list of sessions: %v", err)
		}
		found := false
		for _, s := range refs {
			if s == ref {
				found = true
				break
			}
		}
		if !found {
			return errors.Errorf("unknown ID: %q", ref)
		}
		cm.m.Detach() // Finish existing attach
		cm.m.AttachSession(ref)
	}
	fmt.Fprintf(cm.stdout, "Attached to process %q. Press Ctrl-a-c to switch to the new container\n", id)
	return nil
}

func isProcessID(ctx context.Context, c types.Monitor, ref string) (bool, error) {
	infos, err := c.ListProcesses(ctx)
	if err != nil {
		return false, err
	}
	for _, p := range infos {
		if p.ProcessID == ref {
			return true, nil
		}
	}
	return false, nil
}
