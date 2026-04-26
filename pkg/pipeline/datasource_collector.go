package pipeline

import (
	"context"

	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/observability"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// DataSourceCollector wraps datasource.Source to implement Collector.
type DataSourceCollector struct {
	source datasource.Source
}

// NewDataSourceCollector creates a new DataSourceCollector.
func NewDataSourceCollector(source datasource.Source) *DataSourceCollector {
	return &DataSourceCollector{source: source}
}

// Collect collects runtime events from a pod using the wrapped datasource.
func (c *DataSourceCollector) Collect(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
	events, err := c.source.EventsForPod(ctx, req.Pod, datasource.QueryOptions{
		EventTypes: req.EventTypes,
		Parameters: req.Parameters,
	})
	if err != nil {
		return nil, err
	}
	for _, ev := range events {
		observability.IncDatasourceEventCollected(ev.Type)
	}
	return events, nil
}
