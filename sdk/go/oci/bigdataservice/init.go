// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bigdataservice

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
	case "oci:BigDataService/autoScalingConfiguration:AutoScalingConfiguration":
		r = &AutoScalingConfiguration{}
	case "oci:BigDataService/bdsCapacityReport:BdsCapacityReport":
		r = &BdsCapacityReport{}
	case "oci:BigDataService/bdsInstance:BdsInstance":
		r = &BdsInstance{}
	case "oci:BigDataService/bdsInstanceApiKey:BdsInstanceApiKey":
		r = &BdsInstanceApiKey{}
	case "oci:BigDataService/bdsInstanceIdentityConfiguration:BdsInstanceIdentityConfiguration":
		r = &BdsInstanceIdentityConfiguration{}
	case "oci:BigDataService/bdsInstanceMetastoreConfig:BdsInstanceMetastoreConfig":
		r = &BdsInstanceMetastoreConfig{}
	case "oci:BigDataService/bdsInstanceNodeBackup:BdsInstanceNodeBackup":
		r = &BdsInstanceNodeBackup{}
	case "oci:BigDataService/bdsInstanceNodeBackupConfiguration:BdsInstanceNodeBackupConfiguration":
		r = &BdsInstanceNodeBackupConfiguration{}
	case "oci:BigDataService/bdsInstanceNodeReplaceConfiguration:BdsInstanceNodeReplaceConfiguration":
		r = &BdsInstanceNodeReplaceConfiguration{}
	case "oci:BigDataService/bdsInstanceOperationCertificateManagementsManagement:BdsInstanceOperationCertificateManagementsManagement":
		r = &BdsInstanceOperationCertificateManagementsManagement{}
	case "oci:BigDataService/bdsInstanceOsPatchAction:BdsInstanceOsPatchAction":
		r = &BdsInstanceOsPatchAction{}
	case "oci:BigDataService/bdsInstancePatchAction:BdsInstancePatchAction":
		r = &BdsInstancePatchAction{}
	case "oci:BigDataService/bdsInstanceReplaceNodeAction:BdsInstanceReplaceNodeAction":
		r = &BdsInstanceReplaceNodeAction{}
	case "oci:BigDataService/bdsInstanceResourcePrincipalConfiguration:BdsInstanceResourcePrincipalConfiguration":
		r = &BdsInstanceResourcePrincipalConfiguration{}
	case "oci:BigDataService/bdsInstanceSoftwareUpdateAction:BdsInstanceSoftwareUpdateAction":
		r = &BdsInstanceSoftwareUpdateAction{}
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
		"BigDataService/autoScalingConfiguration",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsCapacityReport",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstance",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceApiKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceIdentityConfiguration",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceMetastoreConfig",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceNodeBackup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceNodeBackupConfiguration",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceNodeReplaceConfiguration",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceOperationCertificateManagementsManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceOsPatchAction",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstancePatchAction",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceReplaceNodeAction",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceResourcePrincipalConfiguration",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"BigDataService/bdsInstanceSoftwareUpdateAction",
		&module{version},
	)
}
