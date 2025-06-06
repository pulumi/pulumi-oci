// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apmsynthetics

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
	case "oci:ApmSynthetics/config:Config":
		r = &Config{}
	case "oci:ApmSynthetics/dedicatedVantagePoint:DedicatedVantagePoint":
		r = &DedicatedVantagePoint{}
	case "oci:ApmSynthetics/onPremiseVantagePoint:OnPremiseVantagePoint":
		r = &OnPremiseVantagePoint{}
	case "oci:ApmSynthetics/onPremiseVantagePointWorker:OnPremiseVantagePointWorker":
		r = &OnPremiseVantagePointWorker{}
	case "oci:ApmSynthetics/script:Script":
		r = &Script{}
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
		"ApmSynthetics/config",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"ApmSynthetics/dedicatedVantagePoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"ApmSynthetics/onPremiseVantagePoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"ApmSynthetics/onPremiseVantagePointWorker",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"ApmSynthetics/script",
		&module{version},
	)
}
