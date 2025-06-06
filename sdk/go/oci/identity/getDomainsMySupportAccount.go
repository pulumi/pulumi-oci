// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific My Support Account resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get a user's own support account.
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
//			_, err := identity.GetDomainsMySupportAccount(ctx, &identity.GetDomainsMySupportAccountArgs{
//				IdcsEndpoint:              testDomain.Url,
//				MySupportAccountId:        testMySupportAccountOciIdentityDomainsMySupportAccount.Id,
//				Authorization:             pulumi.StringRef(mySupportAccountAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(mySupportAccountResourceTypeSchemaVersion),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsMySupportAccount(ctx *pulumi.Context, args *LookupDomainsMySupportAccountArgs, opts ...pulumi.InvokeOption) (*LookupDomainsMySupportAccountResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsMySupportAccountResult
	err := ctx.Invoke("oci:Identity/getDomainsMySupportAccount:getDomainsMySupportAccount", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMySupportAccount.
type LookupDomainsMySupportAccountArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// ID of the resource
	MySupportAccountId string `pulumi:"mySupportAccountId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsMySupportAccount.
type LookupDomainsMySupportAccountResult struct {
	Authorization *string `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsMySupportAccountIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                    `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsMySupportAccountIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas              []GetDomainsMySupportAccountMeta `pulumi:"metas"`
	MySupportAccountId string                           `pulumi:"mySupportAccountId"`
	// User Support Account Provider
	MySupportAccountProvider string `pulumi:"mySupportAccountProvider"`
	// User's ocid
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// A list of tags on this resource.
	Tags []GetDomainsMySupportAccountTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// User Support Account Token
	Token string `pulumi:"token"`
	// User Support User Id
	UserId string `pulumi:"userId"`
	// User linked to Support Account
	Users []GetDomainsMySupportAccountUser `pulumi:"users"`
}

func LookupDomainsMySupportAccountOutput(ctx *pulumi.Context, args LookupDomainsMySupportAccountOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsMySupportAccountResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDomainsMySupportAccountResultOutput, error) {
			args := v.(LookupDomainsMySupportAccountArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsMySupportAccount:getDomainsMySupportAccount", args, LookupDomainsMySupportAccountResultOutput{}, options).(LookupDomainsMySupportAccountResultOutput), nil
		}).(LookupDomainsMySupportAccountResultOutput)
}

// A collection of arguments for invoking getDomainsMySupportAccount.
type LookupDomainsMySupportAccountOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// ID of the resource
	MySupportAccountId pulumi.StringInput `pulumi:"mySupportAccountId"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsMySupportAccountOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMySupportAccountArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMySupportAccount.
type LookupDomainsMySupportAccountResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsMySupportAccountResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsMySupportAccountResult)(nil)).Elem()
}

func (o LookupDomainsMySupportAccountResultOutput) ToLookupDomainsMySupportAccountResultOutput() LookupDomainsMySupportAccountResultOutput {
	return o
}

func (o LookupDomainsMySupportAccountResultOutput) ToLookupDomainsMySupportAccountResultOutputWithContext(ctx context.Context) LookupDomainsMySupportAccountResultOutput {
	return o
}

func (o LookupDomainsMySupportAccountResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsMySupportAccountResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsMySupportAccountResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsMySupportAccountResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsMySupportAccountResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsMySupportAccountResultOutput) IdcsCreatedBies() GetDomainsMySupportAccountIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []GetDomainsMySupportAccountIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsMySupportAccountIdcsCreatedByArrayOutput)
}

func (o LookupDomainsMySupportAccountResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsMySupportAccountResultOutput) IdcsLastModifiedBies() GetDomainsMySupportAccountIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []GetDomainsMySupportAccountIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsMySupportAccountIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsMySupportAccountResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsMySupportAccountResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsMySupportAccountResultOutput) Metas() GetDomainsMySupportAccountMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []GetDomainsMySupportAccountMeta { return v.Metas }).(GetDomainsMySupportAccountMetaArrayOutput)
}

func (o LookupDomainsMySupportAccountResultOutput) MySupportAccountId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.MySupportAccountId }).(pulumi.StringOutput)
}

// User Support Account Provider
func (o LookupDomainsMySupportAccountResultOutput) MySupportAccountProvider() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.MySupportAccountProvider }).(pulumi.StringOutput)
}

// User's ocid
func (o LookupDomainsMySupportAccountResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsMySupportAccountResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsMySupportAccountResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// A list of tags on this resource.
func (o LookupDomainsMySupportAccountResultOutput) Tags() GetDomainsMySupportAccountTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []GetDomainsMySupportAccountTag { return v.Tags }).(GetDomainsMySupportAccountTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsMySupportAccountResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// User Support Account Token
func (o LookupDomainsMySupportAccountResultOutput) Token() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.Token }).(pulumi.StringOutput)
}

// User Support User Id
func (o LookupDomainsMySupportAccountResultOutput) UserId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) string { return v.UserId }).(pulumi.StringOutput)
}

// User linked to Support Account
func (o LookupDomainsMySupportAccountResultOutput) Users() GetDomainsMySupportAccountUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsMySupportAccountResult) []GetDomainsMySupportAccountUser { return v.Users }).(GetDomainsMySupportAccountUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsMySupportAccountResultOutput{})
}
