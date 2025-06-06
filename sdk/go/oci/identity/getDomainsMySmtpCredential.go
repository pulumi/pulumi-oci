// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific My Smtp Credential resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get a user's own SMTP credential.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.GetDomainsMySmtpCredential(ctx, &identity.GetDomainsMySmtpCredentialArgs{
//				IdcsEndpoint:              testDomain.Url,
//				MySmtpCredentialId:        testSmtpCredential.Id,
//				Authorization:             pulumi.StringRef(mySmtpCredentialAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(mySmtpCredentialResourceTypeSchemaVersion),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsMySmtpCredential(ctx *pulumi.Context, args *LookupDomainsMySmtpCredentialArgs, opts ...pulumi.InvokeOption) (*LookupDomainsMySmtpCredentialResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsMySmtpCredentialResult
	err := ctx.Invoke("oci:Identity/getDomainsMySmtpCredential:getDomainsMySmtpCredential", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMySmtpCredential.
type LookupDomainsMySmtpCredentialArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// ID of the resource
	MySmtpCredentialId string `pulumi:"mySmtpCredentialId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsMySmtpCredential.
type LookupDomainsMySmtpCredentialResult struct {
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
	IdcsCreatedBies []GetDomainsMySmtpCredentialIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                    `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsMySmtpCredentialIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas              []GetDomainsMySmtpCredentialMeta `pulumi:"metas"`
	MySmtpCredentialId string                           `pulumi:"mySmtpCredentialId"`
	// User's ocid
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// User credential status
	Status string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []GetDomainsMySmtpCredentialTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// User name
	UserName string `pulumi:"userName"`
	// User linked to smtp credential
	Users []GetDomainsMySmtpCredentialUser `pulumi:"users"`
}

func LookupDomainsMySmtpCredentialOutput(ctx *pulumi.Context, args LookupDomainsMySmtpCredentialOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsMySmtpCredentialResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDomainsMySmtpCredentialResultOutput, error) {
			args := v.(LookupDomainsMySmtpCredentialArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsMySmtpCredential:getDomainsMySmtpCredential", args, LookupDomainsMySmtpCredentialResultOutput{}, options).(LookupDomainsMySmtpCredentialResultOutput), nil
		}).(LookupDomainsMySmtpCredentialResultOutput)
}

// A collection of arguments for invoking getDomainsMySmtpCredential.
type LookupDomainsMySmtpCredentialOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// ID of the resource
	MySmtpCredentialId pulumi.StringInput `pulumi:"mySmtpCredentialId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsMySmtpCredentialOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMySmtpCredentialArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMySmtpCredential.
type LookupDomainsMySmtpCredentialResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsMySmtpCredentialResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMySmtpCredentialResult)(nil)).Elem()
}

func (o LookupDomainsMySmtpCredentialResultOutput) ToLookupDomainsMySmtpCredentialResultOutput() LookupDomainsMySmtpCredentialResultOutput {
	return o
}

func (o LookupDomainsMySmtpCredentialResultOutput) ToLookupDomainsMySmtpCredentialResultOutputWithContext(ctx context.Context) LookupDomainsMySmtpCredentialResultOutput {
	return o
}

func (o LookupDomainsMySmtpCredentialResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsMySmtpCredentialResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsMySmtpCredentialResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Description
func (o LookupDomainsMySmtpCredentialResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.Description }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsMySmtpCredentialResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// User credential expires on
func (o LookupDomainsMySmtpCredentialResultOutput) ExpiresOn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.ExpiresOn }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsMySmtpCredentialResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsMySmtpCredentialResultOutput) IdcsCreatedBies() GetDomainsMySmtpCredentialIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []GetDomainsMySmtpCredentialIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsMySmtpCredentialIdcsCreatedByArrayOutput)
}

func (o LookupDomainsMySmtpCredentialResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsMySmtpCredentialResultOutput) IdcsLastModifiedBies() GetDomainsMySmtpCredentialIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []GetDomainsMySmtpCredentialIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsMySmtpCredentialIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsMySmtpCredentialResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsMySmtpCredentialResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsMySmtpCredentialResultOutput) Metas() GetDomainsMySmtpCredentialMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []GetDomainsMySmtpCredentialMeta { return v.Metas }).(GetDomainsMySmtpCredentialMetaArrayOutput)
}

func (o LookupDomainsMySmtpCredentialResultOutput) MySmtpCredentialId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.MySmtpCredentialId }).(pulumi.StringOutput)
}

// User's ocid
func (o LookupDomainsMySmtpCredentialResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsMySmtpCredentialResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsMySmtpCredentialResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// User credential status
func (o LookupDomainsMySmtpCredentialResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.Status }).(pulumi.StringOutput)
}

// A list of tags on this resource.
func (o LookupDomainsMySmtpCredentialResultOutput) Tags() GetDomainsMySmtpCredentialTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []GetDomainsMySmtpCredentialTag { return v.Tags }).(GetDomainsMySmtpCredentialTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsMySmtpCredentialResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// User name
func (o LookupDomainsMySmtpCredentialResultOutput) UserName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) string { return v.UserName }).(pulumi.StringOutput)
}

// User linked to smtp credential
func (o LookupDomainsMySmtpCredentialResultOutput) Users() GetDomainsMySmtpCredentialUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySmtpCredentialResult) []GetDomainsMySmtpCredentialUser { return v.Users }).(GetDomainsMySmtpCredentialUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsMySmtpCredentialResultOutput{})
}
