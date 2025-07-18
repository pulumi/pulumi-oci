// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package generativeai

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "oci:GenerativeAi/agentAgent:AgentAgent":
		r = &AgentAgent{}
	case "oci:GenerativeAi/agentAgentEndpoint:AgentAgentEndpoint":
		r = &AgentAgentEndpoint{}
	case "oci:GenerativeAi/agentDataIngestionJob:AgentDataIngestionJob":
		r = &AgentDataIngestionJob{}
	case "oci:GenerativeAi/agentDataSource:AgentDataSource":
		r = &AgentDataSource{}
	case "oci:GenerativeAi/agentKnowledgeBase:AgentKnowledgeBase":
		r = &AgentKnowledgeBase{}
	case "oci:GenerativeAi/agentTool:AgentTool":
		r = &AgentTool{}
	case "oci:GenerativeAi/dedicatedAiCluster:DedicatedAiCluster":
		r = &DedicatedAiCluster{}
	case "oci:GenerativeAi/endpoint:Endpoint":
		r = &Endpoint{}
	case "oci:GenerativeAi/model:Model":
		r = &Model{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := internal.PkgVersion()
	if err != nil {
		version = semver.Version{Major: 1}
	}
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentAgent",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentAgentEndpoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentDataIngestionJob",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentDataSource",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentKnowledgeBase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/agentTool",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/dedicatedAiCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/endpoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"GenerativeAi/model",
		&module{version},
	)
}
