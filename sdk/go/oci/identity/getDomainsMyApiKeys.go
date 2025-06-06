// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of My Api Keys in Oracle Cloud Infrastructure Identity Domains service.
//
// Search for a user's own API key.
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
//			_, err := identity.GetDomainsMyApiKeys(ctx, &identity.GetDomainsMyApiKeysArgs{
//				IdcsEndpoint:              testDomain.Url,
//				MyApiKeyCount:             pulumi.IntRef(myApiKeyMyApiKeyCount),
//				MyApiKeyFilter:            pulumi.StringRef(myApiKeyMyApiKeyFilter),
//				Authorization:             pulumi.StringRef(myApiKeyAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(myApiKeyResourceTypeSchemaVersion),
//				StartIndex:                pulumi.IntRef(myApiKeyStartIndex),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDomainsMyApiKeys(ctx *pulumi.Context, args *GetDomainsMyApiKeysArgs, opts ...pulumi.InvokeOption) (*GetDomainsMyApiKeysResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDomainsMyApiKeysResult
	err := ctx.Invoke("oci:Identity/getDomainsMyApiKeys:getDomainsMyApiKeys", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMyApiKeys.
type GetDomainsMyApiKeysArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	MyApiKeyCount *int `pulumi:"myApiKeyCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	MyApiKeyFilter *string `pulumi:"myApiKeyFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    *string `pulumi:"sortBy"`
	SortOrder                 *string `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex *int `pulumi:"startIndex"`
}

// A collection of values returned by getDomainsMyApiKeys.
type GetDomainsMyApiKeysResult struct {
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id             string  `pulumi:"id"`
	IdcsEndpoint   string  `pulumi:"idcsEndpoint"`
	ItemsPerPage   int     `pulumi:"itemsPerPage"`
	MyApiKeyCount  *int    `pulumi:"myApiKeyCount"`
	MyApiKeyFilter *string `pulumi:"myApiKeyFilter"`
	// The list of my_api_keys.
	MyApiKeys                 []GetDomainsMyApiKeysMyApiKey `pulumi:"myApiKeys"`
	ResourceTypeSchemaVersion *string                       `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas      []string `pulumi:"schemas"`
	SortBy       *string  `pulumi:"sortBy"`
	SortOrder    *string  `pulumi:"sortOrder"`
	StartIndex   *int     `pulumi:"startIndex"`
	TotalResults int      `pulumi:"totalResults"`
}

func GetDomainsMyApiKeysOutput(ctx *pulumi.Context, args GetDomainsMyApiKeysOutputArgs, opts ...pulumi.InvokeOption) GetDomainsMyApiKeysResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDomainsMyApiKeysResultOutput, error) {
			args := v.(GetDomainsMyApiKeysArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsMyApiKeys:getDomainsMyApiKeys", args, GetDomainsMyApiKeysResultOutput{}, options).(GetDomainsMyApiKeysResultOutput), nil
		}).(GetDomainsMyApiKeysResultOutput)
}

// A collection of arguments for invoking getDomainsMyApiKeys.
type GetDomainsMyApiKeysOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	MyApiKeyCount pulumi.IntPtrInput `pulumi:"myApiKeyCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	MyApiKeyFilter pulumi.StringPtrInput `pulumi:"myApiKeyFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    pulumi.StringPtrInput `pulumi:"sortBy"`
	SortOrder                 pulumi.StringPtrInput `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex pulumi.IntPtrInput `pulumi:"startIndex"`
}

func (GetDomainsMyApiKeysOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsMyApiKeysArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMyApiKeys.
type GetDomainsMyApiKeysResultOutput struct{ *pulumi.OutputState }

func (GetDomainsMyApiKeysResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsMyApiKeysResult)(nil)).Elem()
}

func (o GetDomainsMyApiKeysResultOutput) ToGetDomainsMyApiKeysResultOutput() GetDomainsMyApiKeysResultOutput {
	return o
}

func (o GetDomainsMyApiKeysResultOutput) ToGetDomainsMyApiKeysResultOutputWithContext(ctx context.Context) GetDomainsMyApiKeysResultOutput {
	return o
}

func (o GetDomainsMyApiKeysResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyApiKeysResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDomainsMyApiKeysResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetDomainsMyApiKeysResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

func (o GetDomainsMyApiKeysResultOutput) ItemsPerPage() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) int { return v.ItemsPerPage }).(pulumi.IntOutput)
}

func (o GetDomainsMyApiKeysResultOutput) MyApiKeyCount() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *int { return v.MyApiKeyCount }).(pulumi.IntPtrOutput)
}

func (o GetDomainsMyApiKeysResultOutput) MyApiKeyFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.MyApiKeyFilter }).(pulumi.StringPtrOutput)
}

// The list of my_api_keys.
func (o GetDomainsMyApiKeysResultOutput) MyApiKeys() GetDomainsMyApiKeysMyApiKeyArrayOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) []GetDomainsMyApiKeysMyApiKey { return v.MyApiKeys }).(GetDomainsMyApiKeysMyApiKeyArrayOutput)
}

func (o GetDomainsMyApiKeysResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o GetDomainsMyApiKeysResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

func (o GetDomainsMyApiKeysResultOutput) SortBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.SortBy }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyApiKeysResultOutput) SortOrder() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *string { return v.SortOrder }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyApiKeysResultOutput) StartIndex() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) *int { return v.StartIndex }).(pulumi.IntPtrOutput)
}

func (o GetDomainsMyApiKeysResultOutput) TotalResults() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsMyApiKeysResult) int { return v.TotalResults }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDomainsMyApiKeysResultOutput{})
}
