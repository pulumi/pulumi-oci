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

// This data source provides details about a specific Security Question resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get a security question.
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
//			_, err := Identity.GetDomainsSecurityQuestion(ctx, &identity.GetDomainsSecurityQuestionArgs{
//				IdcsEndpoint:       data.Oci_identity_domain.Test_domain.Url,
//				SecurityQuestionId: pulumi.StringRef(oci_identity_domains_security_question.Test_security_question.Id),
//				AttributeSets: []string{
//					"all",
//				},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(_var.Security_question_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.Security_question_resource_type_schema_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsSecurityQuestion(ctx *pulumi.Context, args *LookupDomainsSecurityQuestionArgs, opts ...pulumi.InvokeOption) (*LookupDomainsSecurityQuestionResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsSecurityQuestionResult
	err := ctx.Invoke("oci:Identity/getDomainsSecurityQuestion:getDomainsSecurityQuestion", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsSecurityQuestion.
type LookupDomainsSecurityQuestionArgs struct {
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
	// ID of the resource
	SecurityQuestionId *string `pulumi:"securityQuestionId"`
}

// A collection of values returned by getDomainsSecurityQuestion.
type LookupDomainsSecurityQuestionResult struct {
	// This indicates if the question is selected by the Security Admin and is available for the end user.
	Active        bool     `pulumi:"active"`
	AttributeSets []string `pulumi:"attributeSets"`
	Attributes    *string  `pulumi:"attributes"`
	Authorization *string  `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
	ExternalId string `pulumi:"externalId"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsSecurityQuestionIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                    `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsSecurityQuestionIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsSecurityQuestionMeta `pulumi:"metas"`
	// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
	Ocid string `pulumi:"ocid"`
	// Locale values for the Question
	QuestionTexts             []GetDomainsSecurityQuestionQuestionText `pulumi:"questionTexts"`
	ResourceTypeSchemaVersion *string                                  `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas            []string `pulumi:"schemas"`
	SecurityQuestionId *string  `pulumi:"securityQuestionId"`
	// A list of tags on this resource.
	Tags []GetDomainsSecurityQuestionTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// This indicates if the question is a Custom Question added by the Security Admin.
	Type string `pulumi:"type"`
}

func LookupDomainsSecurityQuestionOutput(ctx *pulumi.Context, args LookupDomainsSecurityQuestionOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsSecurityQuestionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDomainsSecurityQuestionResult, error) {
			args := v.(LookupDomainsSecurityQuestionArgs)
			r, err := LookupDomainsSecurityQuestion(ctx, &args, opts...)
			var s LookupDomainsSecurityQuestionResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDomainsSecurityQuestionResultOutput)
}

// A collection of arguments for invoking getDomainsSecurityQuestion.
type LookupDomainsSecurityQuestionOutputArgs struct {
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
	// ID of the resource
	SecurityQuestionId pulumi.StringPtrInput `pulumi:"securityQuestionId"`
}

func (LookupDomainsSecurityQuestionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsSecurityQuestionArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsSecurityQuestion.
type LookupDomainsSecurityQuestionResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsSecurityQuestionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsSecurityQuestionResult)(nil)).Elem()
}

func (o LookupDomainsSecurityQuestionResultOutput) ToLookupDomainsSecurityQuestionResultOutput() LookupDomainsSecurityQuestionResultOutput {
	return o
}

func (o LookupDomainsSecurityQuestionResultOutput) ToLookupDomainsSecurityQuestionResultOutputWithContext(ctx context.Context) LookupDomainsSecurityQuestionResultOutput {
	return o
}

func (o LookupDomainsSecurityQuestionResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupDomainsSecurityQuestionResult] {
	return pulumix.Output[LookupDomainsSecurityQuestionResult]{
		OutputState: o.OutputState,
	}
}

// This indicates if the question is selected by the Security Admin and is available for the end user.
func (o LookupDomainsSecurityQuestionResultOutput) Active() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) bool { return v.Active }).(pulumi.BoolOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsSecurityQuestionResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsSecurityQuestionResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsSecurityQuestionResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
func (o LookupDomainsSecurityQuestionResultOutput) ExternalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.ExternalId }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsSecurityQuestionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsSecurityQuestionResultOutput) IdcsCreatedBies() GetDomainsSecurityQuestionIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []GetDomainsSecurityQuestionIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsSecurityQuestionIdcsCreatedByArrayOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsSecurityQuestionResultOutput) IdcsLastModifiedBies() GetDomainsSecurityQuestionIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []GetDomainsSecurityQuestionIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsSecurityQuestionIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsSecurityQuestionResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsSecurityQuestionResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsSecurityQuestionResultOutput) Metas() GetDomainsSecurityQuestionMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []GetDomainsSecurityQuestionMeta { return v.Metas }).(GetDomainsSecurityQuestionMetaArrayOutput)
}

// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
func (o LookupDomainsSecurityQuestionResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.Ocid }).(pulumi.StringOutput)
}

// Locale values for the Question
func (o LookupDomainsSecurityQuestionResultOutput) QuestionTexts() GetDomainsSecurityQuestionQuestionTextArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []GetDomainsSecurityQuestionQuestionText {
		return v.QuestionTexts
	}).(GetDomainsSecurityQuestionQuestionTextArrayOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsSecurityQuestionResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsSecurityQuestionResultOutput) SecurityQuestionId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) *string { return v.SecurityQuestionId }).(pulumi.StringPtrOutput)
}

// A list of tags on this resource.
func (o LookupDomainsSecurityQuestionResultOutput) Tags() GetDomainsSecurityQuestionTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) []GetDomainsSecurityQuestionTag { return v.Tags }).(GetDomainsSecurityQuestionTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsSecurityQuestionResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// This indicates if the question is a Custom Question added by the Security Admin.
func (o LookupDomainsSecurityQuestionResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsSecurityQuestionResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsSecurityQuestionResultOutput{})
}