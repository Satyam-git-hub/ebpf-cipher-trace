package metadata

import (
	"context"
)

type Enricher interface {
	Enrich(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error)
}

type K8sEnricher struct {
	// K8s client would go here
}

func NewK8sEnricher() *K8sEnricher {
	return &K8sEnricher{}
}

func (e *K8sEnricher) Enrich(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
	// Logic to query K8s API based on PID/ContainerID from data
	return data, nil
}

type DockerEnricher struct {
	// Docker client would go here
}

func NewDockerEnricher() *DockerEnricher {
	return &DockerEnricher{}
}

func (e *DockerEnricher) Enrich(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
	// Logic to query Docker API
	return data, nil
}
