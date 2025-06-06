// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waas

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
	case "oci:Waas/addressList:AddressList":
		r = &AddressList{}
	case "oci:Waas/certificate:Certificate":
		r = &Certificate{}
	case "oci:Waas/customProtectionRule:CustomProtectionRule":
		r = &CustomProtectionRule{}
	case "oci:Waas/httpRedirect:HttpRedirect":
		r = &HttpRedirect{}
	case "oci:Waas/policy:Policy":
		r = &Policy{}
	case "oci:Waas/protectionRule:ProtectionRule":
		r = &ProtectionRule{}
	case "oci:Waas/purgeCache:PurgeCache":
		r = &PurgeCache{}
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
		"Waas/addressList",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/certificate",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/customProtectionRule",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/httpRedirect",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/policy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/protectionRule",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Waas/purgeCache",
		&module{version},
	)
}
