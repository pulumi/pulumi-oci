// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

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
	case "oci:Identity/apiKey:ApiKey":
		r = &ApiKey{}
	case "oci:Identity/authToken:AuthToken":
		r = &AuthToken{}
	case "oci:Identity/authenticationPolicy:AuthenticationPolicy":
		r = &AuthenticationPolicy{}
	case "oci:Identity/compartment:Compartment":
		r = &Compartment{}
	case "oci:Identity/customerSecretKey:CustomerSecretKey":
		r = &CustomerSecretKey{}
	case "oci:Identity/dbCredential:DbCredential":
		r = &DbCredential{}
	case "oci:Identity/domain:Domain":
		r = &Domain{}
	case "oci:Identity/domainReplicationToRegion:DomainReplicationToRegion":
		r = &DomainReplicationToRegion{}
	case "oci:Identity/dynamicGroup:DynamicGroup":
		r = &DynamicGroup{}
	case "oci:Identity/group:Group":
		r = &Group{}
	case "oci:Identity/identityProvider:IdentityProvider":
		r = &IdentityProvider{}
	case "oci:Identity/idpGroupMapping:IdpGroupMapping":
		r = &IdpGroupMapping{}
	case "oci:Identity/importStandardTagsManagement:ImportStandardTagsManagement":
		r = &ImportStandardTagsManagement{}
	case "oci:Identity/networkSource:NetworkSource":
		r = &NetworkSource{}
	case "oci:Identity/policy:Policy":
		r = &Policy{}
	case "oci:Identity/smtpCredential:SmtpCredential":
		r = &SmtpCredential{}
	case "oci:Identity/swiftPassword:SwiftPassword":
		r = &SwiftPassword{}
	case "oci:Identity/tag:Tag":
		r = &Tag{}
	case "oci:Identity/tagDefault:TagDefault":
		r = &TagDefault{}
	case "oci:Identity/tagNamespace:TagNamespace":
		r = &TagNamespace{}
	case "oci:Identity/uiPassword:UiPassword":
		r = &UiPassword{}
	case "oci:Identity/user:User":
		r = &User{}
	case "oci:Identity/userCapabilitiesManagement:UserCapabilitiesManagement":
		r = &UserCapabilitiesManagement{}
	case "oci:Identity/userGroupMembership:UserGroupMembership":
		r = &UserGroupMembership{}
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
		"Identity/apiKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/authToken",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/authenticationPolicy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/compartment",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/customerSecretKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/dbCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domain",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainReplicationToRegion",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/dynamicGroup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/group",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/identityProvider",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/idpGroupMapping",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/importStandardTagsManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/networkSource",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/policy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/smtpCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/swiftPassword",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/tag",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/tagDefault",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/tagNamespace",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/uiPassword",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/user",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/userCapabilitiesManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/userGroupMembership",
		&module{version},
	)
}