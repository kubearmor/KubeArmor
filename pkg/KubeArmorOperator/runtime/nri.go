package runtime

import (
	"context"
	"slices"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"go.uber.org/zap"
)

var (
	_ stub.SynchronizeInterface     = (*NRIHandler)(nil)
	_ stub.CreateContainerInterface = (*NRIHandler)(nil)
)

type NRIHandler struct {
	stub   stub.Stub
	logger *NRILogger

	targetID string
	found    chan struct{}
	errors   chan error
}

func NewNRIPugin(targetID, socketPath string) (*NRIHandler, error) {
	nri := &NRIHandler{
		targetID: targetID,
		found:    make(chan struct{}, 1),
	}

	logger := newNRILogger()

	s, err := stub.New(nri,
		stub.WithPluginName("snitch-has-container"),
		stub.WithPluginIdx("99"),
		stub.WithSocketPath(socketPath),
		stub.WithLogger(logger),
	)
	if err != nil {
		return nil, err
	}

	nri.stub = s
	nri.logger = logger

	return nri, nil
}

func (p *NRIHandler) Start(ctx context.Context) {
	go func() {
		if err := p.stub.Run(ctx); err != nil {
			select {
			case p.errors <- err:
			default:
			}
		}
	}()
}

func (p *NRIHandler) Stop() {
	p.stub.Stop()
	_ = p.logger.Sync()
}

func (p *NRIHandler) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	found := slices.ContainsFunc(containers, func(c *api.Container) bool {
		return c.Id == p.targetID
	})

	if found {
		select {
		case p.found <- struct{}{}:
		default:
		}
	}
	return nil, nil
}

func (p *NRIHandler) CreateContainer(context.Context, *api.PodSandbox, *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	return nil, nil, nil
}

func (p *NRIHandler) WaitForContainer(ctx context.Context) (bool, error) {
	select {
	case <-p.found:
		return true, nil
	case err := <-p.errors:
		return false, err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

type NRILogger struct {
	*zap.SugaredLogger
}

func newNRILogger() *NRILogger {
	logger, _ := zap.NewProduction()

	return &NRILogger{
		SugaredLogger: logger.Sugar(),
	}
}

func (l *NRILogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	l.SugaredLogger.Debugf(format, args...)
}

func (l *NRILogger) Infof(ctx context.Context, format string, args ...interface{}) {
	l.SugaredLogger.Infof(format, args...)
}

func (l *NRILogger) Warnf(ctx context.Context, format string, args ...interface{}) {
	l.SugaredLogger.Warnf(format, args...)
}

func (l *NRILogger) Errorf(ctx context.Context, format string, args ...interface{}) {
	l.SugaredLogger.Errorf(format, args...)
}
