// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Account Recovery Setting resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get an account recovery setting.
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
//			_, err := Identity.GetDomainsAccountRecoverySetting(ctx, &identity.GetDomainsAccountRecoverySettingArgs{
//				AccountRecoverySettingId: oci_identity_domains_account_recovery_setting.Test_account_recovery_setting.Id,
//				IdcsEndpoint:             data.Oci_identity_domain.Test_domain.Url,
//				AttributeSets: []string{
//					"all",
//				},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(_var.Account_recovery_setting_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.Account_recovery_setting_resource_type_schema_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsAccountRecoverySetting(ctx *pulumi.Context, args *LookupDomainsAccountRecoverySettingArgs, opts ...pulumi.InvokeOption) (*LookupDomainsAccountRecoverySettingResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsAccountRecoverySettingResult
	err := ctx.Invoke("oci:Identity/getDomainsAccountRecoverySetting:getDomainsAccountRecoverySetting", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsAccountRecoverySetting.
type LookupDomainsAccountRecoverySettingArgs struct {
	// ID of the resource
	AccountRecoverySettingId string `pulumi:"accountRecoverySettingId"`
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsAccountRecoverySetting.
type LookupDomainsAccountRecoverySettingResult struct {
	AccountRecoverySettingId string   `pulumi:"accountRecoverySettingId"`
	AttributeSets            []string `pulumi:"attributeSets"`
	Attributes               *string  `pulumi:"attributes"`
	Authorization            *string  `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
	ExternalId string `pulumi:"externalId"`
	// The account recovery factor used (for example, email, mobile number (SMS), security questions, mobile application push or TOTP) to verify the identity of the user and reset the user's password.
	Factors []string `pulumi:"factors"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsAccountRecoverySettingIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                          `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsAccountRecoverySettingIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// Indicates how many minutes to disable account recovery for the user. The default value is 30 metric minutes.
	LockoutDuration int `pulumi:"lockoutDuration"`
	// Indicates the maximum number of failed account recovery attempts allowed for the user.
	MaxIncorrectAttempts int `pulumi:"maxIncorrectAttempts"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsAccountRecoverySettingMeta `pulumi:"metas"`
	// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// A list of tags on this resource.
	Tags []GetDomainsAccountRecoverySettingTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
}

func LookupDomainsAccountRecoverySettingOutput(ctx *pulumi.Context, args LookupDomainsAccountRecoverySettingOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsAccountRecoverySettingResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDomainsAccountRecoverySettingResult, error) {
			args := v.(LookupDomainsAccountRecoverySettingArgs)
			r, err := LookupDomainsAccountRecoverySetting(ctx, &args, opts...)
			var s LookupDomainsAccountRecoverySettingResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDomainsAccountRecoverySettingResultOutput)
}

// A collection of arguments for invoking getDomainsAccountRecoverySetting.
type LookupDomainsAccountRecoverySettingOutputArgs struct {
	// ID of the resource
	AccountRecoverySettingId pulumi.StringInput `pulumi:"accountRecoverySettingId"`
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsAccountRecoverySettingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsAccountRecoverySettingArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsAccountRecoverySetting.
type LookupDomainsAccountRecoverySettingResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsAccountRecoverySettingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsAccountRecoverySettingResult)(nil)).Elem()
}

func (o LookupDomainsAccountRecoverySettingResultOutput) ToLookupDomainsAccountRecoverySettingResultOutput() LookupDomainsAccountRecoverySettingResultOutput {
	return o
}

func (o LookupDomainsAccountRecoverySettingResultOutput) ToLookupDomainsAccountRecoverySettingResultOutputWithContext(ctx context.Context) LookupDomainsAccountRecoverySettingResultOutput {
	return o
}

func (o LookupDomainsAccountRecoverySettingResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupDomainsAccountRecoverySettingResult] {
	return pulumix.Output[LookupDomainsAccountRecoverySettingResult]{
		OutputState: o.OutputState,
	}
}

func (o LookupDomainsAccountRecoverySettingResultOutput) AccountRecoverySettingId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.AccountRecoverySettingId }).(pulumi.StringOutput)
}

func (o LookupDomainsAccountRecoverySettingResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsAccountRecoverySettingResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsAccountRecoverySettingResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsAccountRecoverySettingResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsAccountRecoverySettingResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsAccountRecoverySettingResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
func (o LookupDomainsAccountRecoverySettingResultOutput) ExternalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.ExternalId }).(pulumi.StringOutput)
}

// The account recovery factor used (for example, email, mobile number (SMS), security questions, mobile application push or TOTP) to verify the identity of the user and reset the user's password.
func (o LookupDomainsAccountRecoverySettingResultOutput) Factors() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []string { return v.Factors }).(pulumi.StringArrayOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsAccountRecoverySettingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsAccountRecoverySettingResultOutput) IdcsCreatedBies() GetDomainsAccountRecoverySettingIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []GetDomainsAccountRecoverySettingIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsAccountRecoverySettingIdcsCreatedByArrayOutput)
}

func (o LookupDomainsAccountRecoverySettingResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsAccountRecoverySettingResultOutput) IdcsLastModifiedBies() GetDomainsAccountRecoverySettingIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []GetDomainsAccountRecoverySettingIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsAccountRecoverySettingIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsAccountRecoverySettingResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsAccountRecoverySettingResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// Indicates how many minutes to disable account recovery for the user. The default value is 30 metric minutes.
func (o LookupDomainsAccountRecoverySettingResultOutput) LockoutDuration() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) int { return v.LockoutDuration }).(pulumi.IntOutput)
}

// Indicates the maximum number of failed account recovery attempts allowed for the user.
func (o LookupDomainsAccountRecoverySettingResultOutput) MaxIncorrectAttempts() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) int { return v.MaxIncorrectAttempts }).(pulumi.IntOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsAccountRecoverySettingResultOutput) Metas() GetDomainsAccountRecoverySettingMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []GetDomainsAccountRecoverySettingMeta {
		return v.Metas
	}).(GetDomainsAccountRecoverySettingMetaArrayOutput)
}

// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
func (o LookupDomainsAccountRecoverySettingResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsAccountRecoverySettingResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsAccountRecoverySettingResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// A list of tags on this resource.
func (o LookupDomainsAccountRecoverySettingResultOutput) Tags() GetDomainsAccountRecoverySettingTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) []GetDomainsAccountRecoverySettingTag { return v.Tags }).(GetDomainsAccountRecoverySettingTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsAccountRecoverySettingResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAccountRecoverySettingResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsAccountRecoverySettingResultOutput{})
}