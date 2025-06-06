// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package kms

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
	case "oci:Kms/ekmsPrivateEndpoint:EkmsPrivateEndpoint":
		r = &EkmsPrivateEndpoint{}
	case "oci:Kms/encryptedData:EncryptedData":
		r = &EncryptedData{}
	case "oci:Kms/generatedKey:GeneratedKey":
		r = &GeneratedKey{}
	case "oci:Kms/key:Key":
		r = &Key{}
	case "oci:Kms/keyVersion:KeyVersion":
		r = &KeyVersion{}
	case "oci:Kms/sign:Sign":
		r = &Sign{}
	case "oci:Kms/vault:Vault":
		r = &Vault{}
	case "oci:Kms/vaultVerification:VaultVerification":
		r = &VaultVerification{}
	case "oci:Kms/verify:Verify":
		r = &Verify{}
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
		"Kms/ekmsPrivateEndpoint",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/encryptedData",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/generatedKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/key",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/keyVersion",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/sign",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/vault",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/vaultVerification",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Kms/verify",
		&module{version},
	)
}
