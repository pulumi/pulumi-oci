// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fusionapps

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/go/oci"
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
	case "oci:FusionApps/fusionEnvironment:FusionEnvironment":
		r = &FusionEnvironment{}
	case "oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser":
		r = &FusionEnvironmentAdminUser{}
	case "oci:FusionApps/fusionEnvironmentDataMaskingActivity:FusionEnvironmentDataMaskingActivity":
		r = &FusionEnvironmentDataMaskingActivity{}
	case "oci:FusionApps/fusionEnvironmentFamily:FusionEnvironmentFamily":
		r = &FusionEnvironmentFamily{}
	case "oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity":
		r = &FusionEnvironmentRefreshActivity{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := oci.PkgVersion()
	if err != nil {
		version = semver.Version{Major: 1}
	}
	pulumi.RegisterResourceModule(
		"oci",
		"FusionApps/fusionEnvironment",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"FusionApps/fusionEnvironmentAdminUser",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"FusionApps/fusionEnvironmentDataMaskingActivity",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"FusionApps/fusionEnvironmentFamily",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"FusionApps/fusionEnvironmentRefreshActivity",
		&module{version},
	)
}