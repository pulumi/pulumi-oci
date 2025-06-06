// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

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
	case "oci:Identity/domainsAccountRecoverySetting:DomainsAccountRecoverySetting":
		r = &DomainsAccountRecoverySetting{}
	case "oci:Identity/domainsApiKey:DomainsApiKey":
		r = &DomainsApiKey{}
	case "oci:Identity/domainsApp:DomainsApp":
		r = &DomainsApp{}
	case "oci:Identity/domainsAppRole:DomainsAppRole":
		r = &DomainsAppRole{}
	case "oci:Identity/domainsApprovalWorkflow:DomainsApprovalWorkflow":
		r = &DomainsApprovalWorkflow{}
	case "oci:Identity/domainsApprovalWorkflowAssignment:DomainsApprovalWorkflowAssignment":
		r = &DomainsApprovalWorkflowAssignment{}
	case "oci:Identity/domainsApprovalWorkflowStep:DomainsApprovalWorkflowStep":
		r = &DomainsApprovalWorkflowStep{}
	case "oci:Identity/domainsAuthToken:DomainsAuthToken":
		r = &DomainsAuthToken{}
	case "oci:Identity/domainsAuthenticationFactorSetting:DomainsAuthenticationFactorSetting":
		r = &DomainsAuthenticationFactorSetting{}
	case "oci:Identity/domainsCloudGate:DomainsCloudGate":
		r = &DomainsCloudGate{}
	case "oci:Identity/domainsCloudGateMapping:DomainsCloudGateMapping":
		r = &DomainsCloudGateMapping{}
	case "oci:Identity/domainsCloudGateServer:DomainsCloudGateServer":
		r = &DomainsCloudGateServer{}
	case "oci:Identity/domainsCondition:DomainsCondition":
		r = &DomainsCondition{}
	case "oci:Identity/domainsCustomerSecretKey:DomainsCustomerSecretKey":
		r = &DomainsCustomerSecretKey{}
	case "oci:Identity/domainsDynamicResourceGroup:DomainsDynamicResourceGroup":
		r = &DomainsDynamicResourceGroup{}
	case "oci:Identity/domainsGrant:DomainsGrant":
		r = &DomainsGrant{}
	case "oci:Identity/domainsGroup:DomainsGroup":
		r = &DomainsGroup{}
	case "oci:Identity/domainsIdentityPropagationTrust:DomainsIdentityPropagationTrust":
		r = &DomainsIdentityPropagationTrust{}
	case "oci:Identity/domainsIdentityProvider:DomainsIdentityProvider":
		r = &DomainsIdentityProvider{}
	case "oci:Identity/domainsIdentitySetting:DomainsIdentitySetting":
		r = &DomainsIdentitySetting{}
	case "oci:Identity/domainsKmsiSetting:DomainsKmsiSetting":
		r = &DomainsKmsiSetting{}
	case "oci:Identity/domainsMyApiKey:DomainsMyApiKey":
		r = &DomainsMyApiKey{}
	case "oci:Identity/domainsMyAuthToken:DomainsMyAuthToken":
		r = &DomainsMyAuthToken{}
	case "oci:Identity/domainsMyCustomerSecretKey:DomainsMyCustomerSecretKey":
		r = &DomainsMyCustomerSecretKey{}
	case "oci:Identity/domainsMyOauth2clientCredential:DomainsMyOauth2clientCredential":
		r = &DomainsMyOauth2clientCredential{}
	case "oci:Identity/domainsMyRequest:DomainsMyRequest":
		r = &DomainsMyRequest{}
	case "oci:Identity/domainsMySmtpCredential:DomainsMySmtpCredential":
		r = &DomainsMySmtpCredential{}
	case "oci:Identity/domainsMySupportAccount:DomainsMySupportAccount":
		r = &DomainsMySupportAccount{}
	case "oci:Identity/domainsMyUserDbCredential:DomainsMyUserDbCredential":
		r = &DomainsMyUserDbCredential{}
	case "oci:Identity/domainsNetworkPerimeter:DomainsNetworkPerimeter":
		r = &DomainsNetworkPerimeter{}
	case "oci:Identity/domainsNotificationSetting:DomainsNotificationSetting":
		r = &DomainsNotificationSetting{}
	case "oci:Identity/domainsOauth2clientCredential:DomainsOauth2clientCredential":
		r = &DomainsOauth2clientCredential{}
	case "oci:Identity/domainsOauthClientCertificate:DomainsOauthClientCertificate":
		r = &DomainsOauthClientCertificate{}
	case "oci:Identity/domainsOauthPartnerCertificate:DomainsOauthPartnerCertificate":
		r = &DomainsOauthPartnerCertificate{}
	case "oci:Identity/domainsPasswordPolicy:DomainsPasswordPolicy":
		r = &DomainsPasswordPolicy{}
	case "oci:Identity/domainsPolicy:DomainsPolicy":
		r = &DomainsPolicy{}
	case "oci:Identity/domainsRule:DomainsRule":
		r = &DomainsRule{}
	case "oci:Identity/domainsSecurityQuestion:DomainsSecurityQuestion":
		r = &DomainsSecurityQuestion{}
	case "oci:Identity/domainsSecurityQuestionSetting:DomainsSecurityQuestionSetting":
		r = &DomainsSecurityQuestionSetting{}
	case "oci:Identity/domainsSelfRegistrationProfile:DomainsSelfRegistrationProfile":
		r = &DomainsSelfRegistrationProfile{}
	case "oci:Identity/domainsSetting:DomainsSetting":
		r = &DomainsSetting{}
	case "oci:Identity/domainsSmtpCredential:DomainsSmtpCredential":
		r = &DomainsSmtpCredential{}
	case "oci:Identity/domainsSocialIdentityProvider:DomainsSocialIdentityProvider":
		r = &DomainsSocialIdentityProvider{}
	case "oci:Identity/domainsUser:DomainsUser":
		r = &DomainsUser{}
	case "oci:Identity/domainsUserDbCredential:DomainsUserDbCredential":
		r = &DomainsUserDbCredential{}
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
	version, err := internal.PkgVersion()
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
		"Identity/domainsAccountRecoverySetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsApiKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsApp",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsAppRole",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsApprovalWorkflow",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsApprovalWorkflowAssignment",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsApprovalWorkflowStep",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsAuthToken",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsAuthenticationFactorSetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsCloudGate",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsCloudGateMapping",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsCloudGateServer",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsCondition",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsCustomerSecretKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsDynamicResourceGroup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsGrant",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsGroup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsIdentityPropagationTrust",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsIdentityProvider",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsIdentitySetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsKmsiSetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyApiKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyAuthToken",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyCustomerSecretKey",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyOauth2clientCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyRequest",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMySmtpCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMySupportAccount",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsMyUserDbCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsNetworkPerimeter",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsNotificationSetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsOauth2clientCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsOauthClientCertificate",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsOauthPartnerCertificate",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsPasswordPolicy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsPolicy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsRule",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSecurityQuestion",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSecurityQuestionSetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSelfRegistrationProfile",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSetting",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSmtpCredential",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsSocialIdentityProvider",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsUser",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Identity/domainsUserDbCredential",
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
