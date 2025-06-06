// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Condition resource in Oracle Cloud Infrastructure Identity Domains service.
//
// Get a condition.
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
//			_, err := identity.GetDomainsCondition(ctx, &identity.GetDomainsConditionArgs{
//				ConditionId:  testConditionOciIdentityDomainsCondition.Id,
//				IdcsEndpoint: testDomain.Url,
//				AttributeSets: []string{
//					"all",
//				},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(conditionAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(conditionResourceTypeSchemaVersion),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsCondition(ctx *pulumi.Context, args *LookupDomainsConditionArgs, opts ...pulumi.InvokeOption) (*LookupDomainsConditionResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsConditionResult
	err := ctx.Invoke("oci:Identity/getDomainsCondition:getDomainsCondition", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsCondition.
type LookupDomainsConditionArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// ID of the resource
	ConditionId string `pulumi:"conditionId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsCondition.
type LookupDomainsConditionResult struct {
	// AttributeName - RHS of condition
	AttributeName string   `pulumi:"attributeName"`
	AttributeSets []string `pulumi:"attributeSets"`
	// attributeValue - RHS of condition
	AttributeValue string  `pulumi:"attributeValue"`
	Attributes     *string `pulumi:"attributes"`
	Authorization  *string `pulumi:"authorization"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	ConditionId     string `pulumi:"conditionId"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Condition Description
	Description string `pulumi:"description"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// Evaluate the condition if this expression returns true, else skip condition evaluation
	EvaluateConditionIf string `pulumi:"evaluateConditionIf"`
	// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value.  The value of the externalId attribute is always issued be the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
	ExternalId string `pulumi:"externalId"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsConditionIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                             `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsConditionIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsConditionMeta `pulumi:"metas"`
	// Condition name
	Name string `pulumi:"name"`
	// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
	Ocid string `pulumi:"ocid"`
	// **SCIM++ Properties:**
	// * caseExact: true
	// * idcsSearchable: false
	// * multiValued: false
	// * mutability: readWrite
	// * required: true
	// * returned: default
	// * type: string
	// * uniqueness: none Operator in the condition. It support all SCIM operators like eq, gt, lt, le, sw etc
	Operator                  string  `pulumi:"operator"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// A list of tags on this resource.
	Tags []GetDomainsConditionTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
}

func LookupDomainsConditionOutput(ctx *pulumi.Context, args LookupDomainsConditionOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsConditionResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDomainsConditionResultOutput, error) {
			args := v.(LookupDomainsConditionArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsCondition:getDomainsCondition", args, LookupDomainsConditionResultOutput{}, options).(LookupDomainsConditionResultOutput), nil
		}).(LookupDomainsConditionResultOutput)
}

// A collection of arguments for invoking getDomainsCondition.
type LookupDomainsConditionOutputArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// ID of the resource
	ConditionId pulumi.StringInput `pulumi:"conditionId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsConditionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsConditionArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsCondition.
type LookupDomainsConditionResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsConditionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsConditionResult)(nil)).Elem()
}

func (o LookupDomainsConditionResultOutput) ToLookupDomainsConditionResultOutput() LookupDomainsConditionResultOutput {
	return o
}

func (o LookupDomainsConditionResultOutput) ToLookupDomainsConditionResultOutputWithContext(ctx context.Context) LookupDomainsConditionResultOutput {
	return o
}

// AttributeName - RHS of condition
func (o LookupDomainsConditionResultOutput) AttributeName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.AttributeName }).(pulumi.StringOutput)
}

func (o LookupDomainsConditionResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

// attributeValue - RHS of condition
func (o LookupDomainsConditionResultOutput) AttributeValue() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.AttributeValue }).(pulumi.StringOutput)
}

func (o LookupDomainsConditionResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsConditionResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsConditionResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

func (o LookupDomainsConditionResultOutput) ConditionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.ConditionId }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsConditionResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Condition Description
func (o LookupDomainsConditionResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.Description }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsConditionResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// Evaluate the condition if this expression returns true, else skip condition evaluation
func (o LookupDomainsConditionResultOutput) EvaluateConditionIf() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.EvaluateConditionIf }).(pulumi.StringOutput)
}

// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value.  The value of the externalId attribute is always issued be the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
func (o LookupDomainsConditionResultOutput) ExternalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.ExternalId }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsConditionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsConditionResultOutput) IdcsCreatedBies() GetDomainsConditionIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []GetDomainsConditionIdcsCreatedBy { return v.IdcsCreatedBies }).(GetDomainsConditionIdcsCreatedByArrayOutput)
}

func (o LookupDomainsConditionResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsConditionResultOutput) IdcsLastModifiedBies() GetDomainsConditionIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []GetDomainsConditionIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsConditionIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsConditionResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsConditionResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsConditionResultOutput) Metas() GetDomainsConditionMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []GetDomainsConditionMeta { return v.Metas }).(GetDomainsConditionMetaArrayOutput)
}

// Condition name
func (o LookupDomainsConditionResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.Name }).(pulumi.StringOutput)
}

// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
func (o LookupDomainsConditionResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.Ocid }).(pulumi.StringOutput)
}

// **SCIM++ Properties:**
// * caseExact: true
// * idcsSearchable: false
// * multiValued: false
// * mutability: readWrite
// * required: true
// * returned: default
// * type: string
// * uniqueness: none Operator in the condition. It support all SCIM operators like eq, gt, lt, le, sw etc
func (o LookupDomainsConditionResultOutput) Operator() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.Operator }).(pulumi.StringOutput)
}

func (o LookupDomainsConditionResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsConditionResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// A list of tags on this resource.
func (o LookupDomainsConditionResultOutput) Tags() GetDomainsConditionTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) []GetDomainsConditionTag { return v.Tags }).(GetDomainsConditionTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsConditionResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsConditionResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsConditionResultOutput{})
}
