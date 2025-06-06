// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific My Customer Secret Key resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get a user's own customer secret key.
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
//			_, err := identity.GetDomainsMyCustomerSecretKey(ctx, &identity.GetDomainsMyCustomerSecretKeyArgs{
//				IdcsEndpoint:              testDomain.Url,
//				MyCustomerSecretKeyId:     testCustomerSecretKey.Id,
//				Authorization:             pulumi.StringRef(myCustomerSecretKeyAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(myCustomerSecretKeyResourceTypeSchemaVersion),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsMyCustomerSecretKey(ctx *pulumi.Context, args *LookupDomainsMyCustomerSecretKeyArgs, opts ...pulumi.InvokeOption) (*LookupDomainsMyCustomerSecretKeyResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsMyCustomerSecretKeyResult
	err := ctx.Invoke("oci:Identity/getDomainsMyCustomerSecretKey:getDomainsMyCustomerSecretKey", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMyCustomerSecretKey.
type LookupDomainsMyCustomerSecretKeyArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// ID of the resource
	MyCustomerSecretKeyId string `pulumi:"myCustomerSecretKeyId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsMyCustomerSecretKey.
type LookupDomainsMyCustomerSecretKeyResult struct {
	// The access key.
	AccessKey     string  `pulumi:"accessKey"`
	Authorization *string `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Description
	Description string `pulumi:"description"`
	// Display Name
	DisplayName string `pulumi:"displayName"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// When the user's credential expire.
	ExpiresOn string `pulumi:"expiresOn"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsMyCustomerSecretKeyIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                       `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsMyCustomerSecretKeyIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas                 []GetDomainsMyCustomerSecretKeyMeta `pulumi:"metas"`
	MyCustomerSecretKeyId string                              `pulumi:"myCustomerSecretKeyId"`
	// The user's OCID.
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// The user's credential status.
	Status string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []GetDomainsMyCustomerSecretKeyTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// User linked to customer secret key
	Users []GetDomainsMyCustomerSecretKeyUser `pulumi:"users"`
}

func LookupDomainsMyCustomerSecretKeyOutput(ctx *pulumi.Context, args LookupDomainsMyCustomerSecretKeyOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsMyCustomerSecretKeyResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDomainsMyCustomerSecretKeyResultOutput, error) {
			args := v.(LookupDomainsMyCustomerSecretKeyArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsMyCustomerSecretKey:getDomainsMyCustomerSecretKey", args, LookupDomainsMyCustomerSecretKeyResultOutput{}, options).(LookupDomainsMyCustomerSecretKeyResultOutput), nil
		}).(LookupDomainsMyCustomerSecretKeyResultOutput)
}

// A collection of arguments for invoking getDomainsMyCustomerSecretKey.
type LookupDomainsMyCustomerSecretKeyOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// ID of the resource
	MyCustomerSecretKeyId pulumi.StringInput `pulumi:"myCustomerSecretKeyId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsMyCustomerSecretKeyOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMyCustomerSecretKeyArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMyCustomerSecretKey.
type LookupDomainsMyCustomerSecretKeyResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsMyCustomerSecretKeyResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMyCustomerSecretKeyResult)(nil)).Elem()
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) ToLookupDomainsMyCustomerSecretKeyResultOutput() LookupDomainsMyCustomerSecretKeyResultOutput {
	return o
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) ToLookupDomainsMyCustomerSecretKeyResultOutputWithContext(ctx context.Context) LookupDomainsMyCustomerSecretKeyResultOutput {
	return o
}

// The access key.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) AccessKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.AccessKey }).(pulumi.StringOutput)
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Description
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.Description }).(pulumi.StringOutput)
}

// Display Name
func (o LookupDomainsMyCustomerSecretKeyResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// When the user's credential expire.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) ExpiresOn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.ExpiresOn }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsMyCustomerSecretKeyResultOutput) IdcsCreatedBies() GetDomainsMyCustomerSecretKeyIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []GetDomainsMyCustomerSecretKeyIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsMyCustomerSecretKeyIdcsCreatedByArrayOutput)
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsMyCustomerSecretKeyResultOutput) IdcsLastModifiedBies() GetDomainsMyCustomerSecretKeyIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []GetDomainsMyCustomerSecretKeyIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsMyCustomerSecretKeyIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Metas() GetDomainsMyCustomerSecretKeyMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []GetDomainsMyCustomerSecretKeyMeta { return v.Metas }).(GetDomainsMyCustomerSecretKeyMetaArrayOutput)
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) MyCustomerSecretKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.MyCustomerSecretKeyId }).(pulumi.StringOutput)
}

// The user's OCID.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsMyCustomerSecretKeyResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// The user's credential status.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.Status }).(pulumi.StringOutput)
}

// A list of tags on this resource.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Tags() GetDomainsMyCustomerSecretKeyTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []GetDomainsMyCustomerSecretKeyTag { return v.Tags }).(GetDomainsMyCustomerSecretKeyTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsMyCustomerSecretKeyResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// User linked to customer secret key
func (o LookupDomainsMyCustomerSecretKeyResultOutput) Users() GetDomainsMyCustomerSecretKeyUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsMyCustomerSecretKeyResult) []GetDomainsMyCustomerSecretKeyUser { return v.Users }).(GetDomainsMyCustomerSecretKeyUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsMyCustomerSecretKeyResultOutput{})
}
