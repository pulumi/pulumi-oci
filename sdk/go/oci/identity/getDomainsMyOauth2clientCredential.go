// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific My O Auth2 Client Credential resource in Oracle Cloud Infrastructure Identity Domains service.
//
// # Get user's oauth2 client credential
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Identity.GetDomainsMyOauth2clientCredential(ctx, &identity.GetDomainsMyOauth2clientCredentialArgs{
//				IdcsEndpoint:               data.Oci_identity_domain.Test_domain.Url,
//				MyOauth2clientCredentialId: oci_identity_domains_my_oauth2client_credential.Test_my_oauth2client_credential.Id,
//				Authorization:              pulumi.StringRef(_var.My_oauth2client_credential_authorization),
//				ResourceTypeSchemaVersion:  pulumi.StringRef(_var.My_oauth2client_credential_resource_type_schema_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsMyOauth2clientCredential(ctx *pulumi.Context, args *LookupDomainsMyOauth2clientCredentialArgs, opts ...pulumi.InvokeOption) (*LookupDomainsMyOauth2clientCredentialResult, error) {
	var rv LookupDomainsMyOauth2clientCredentialResult
	err := ctx.Invoke("oci:Identity/getDomainsMyOauth2clientCredential:getDomainsMyOauth2clientCredential", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMyOauth2clientCredential.
type LookupDomainsMyOauth2clientCredentialArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// ID of the resource
	MyOauth2clientCredentialId string `pulumi:"myOauth2clientCredentialId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsMyOauth2clientCredential.
type LookupDomainsMyOauth2clientCredentialResult struct {
	Authorization *string `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Description
	Description string `pulumi:"description"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// User credential expires on
	ExpiresOn string `pulumi:"expiresOn"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsMyOauth2clientCredentialIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                            `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsMyOauth2clientCredentialIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// Specifies if secret need to be reset
	IsResetSecret bool `pulumi:"isResetSecret"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas                      []GetDomainsMyOauth2clientCredentialMeta `pulumi:"metas"`
	MyOauth2clientCredentialId string                                   `pulumi:"myOauth2clientCredentialId"`
	// User name
	Name string `pulumi:"name"`
	// User's ocid
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// Scopes
	Scopes []GetDomainsMyOauth2clientCredentialScope `pulumi:"scopes"`
	// User credential status
	Status string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []GetDomainsMyOauth2clientCredentialTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// User linked to oauth2 client credential
	Users []GetDomainsMyOauth2clientCredentialUser `pulumi:"users"`
}

func LookupDomainsMyOauth2clientCredentialOutput(ctx *pulumi.Context, args LookupDomainsMyOauth2clientCredentialOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsMyOauth2clientCredentialResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDomainsMyOauth2clientCredentialResult, error) {
			args := v.(LookupDomainsMyOauth2clientCredentialArgs)
			r, err := LookupDomainsMyOauth2clientCredential(ctx, &args, opts...)
			var s LookupDomainsMyOauth2clientCredentialResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDomainsMyOauth2clientCredentialResultOutput)
}

// A collection of arguments for invoking getDomainsMyOauth2clientCredential.
type LookupDomainsMyOauth2clientCredentialOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// ID of the resource
	MyOauth2clientCredentialId pulumi.StringInput `pulumi:"myOauth2clientCredentialId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsMyOauth2clientCredentialOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMyOauth2clientCredentialArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMyOauth2clientCredential.
type LookupDomainsMyOauth2clientCredentialResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsMyOauth2clientCredentialResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMyOauth2clientCredentialResult)(nil)).Elem()
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) ToLookupDomainsMyOauth2clientCredentialResultOutput() LookupDomainsMyOauth2clientCredentialResultOutput {
	return o
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) ToLookupDomainsMyOauth2clientCredentialResultOutputWithContext(ctx context.Context) LookupDomainsMyOauth2clientCredentialResultOutput {
	return o
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Description
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.Description }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// User credential expires on
func (o LookupDomainsMyOauth2clientCredentialResultOutput) ExpiresOn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.ExpiresOn }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsMyOauth2clientCredentialResultOutput) IdcsCreatedBies() GetDomainsMyOauth2clientCredentialIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsMyOauth2clientCredentialIdcsCreatedByArrayOutput)
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsMyOauth2clientCredentialResultOutput) IdcsLastModifiedBies() GetDomainsMyOauth2clientCredentialIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsMyOauth2clientCredentialIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// Specifies if secret need to be reset
func (o LookupDomainsMyOauth2clientCredentialResultOutput) IsResetSecret() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) bool { return v.IsResetSecret }).(pulumi.BoolOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Metas() GetDomainsMyOauth2clientCredentialMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialMeta {
		return v.Metas
	}).(GetDomainsMyOauth2clientCredentialMetaArrayOutput)
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) MyOauth2clientCredentialId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.MyOauth2clientCredentialId }).(pulumi.StringOutput)
}

// User name
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.Name }).(pulumi.StringOutput)
}

// User's ocid
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsMyOauth2clientCredentialResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// Scopes
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Scopes() GetDomainsMyOauth2clientCredentialScopeArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialScope {
		return v.Scopes
	}).(GetDomainsMyOauth2clientCredentialScopeArrayOutput)
}

// User credential status
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.Status }).(pulumi.StringOutput)
}

// A list of tags on this resource.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Tags() GetDomainsMyOauth2clientCredentialTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialTag {
		return v.Tags
	}).(GetDomainsMyOauth2clientCredentialTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsMyOauth2clientCredentialResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// User linked to oauth2 client credential
func (o LookupDomainsMyOauth2clientCredentialResultOutput) Users() GetDomainsMyOauth2clientCredentialUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyOauth2clientCredentialResult) []GetDomainsMyOauth2clientCredentialUser {
		return v.Users
	}).(GetDomainsMyOauth2clientCredentialUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsMyOauth2clientCredentialResultOutput{})
}