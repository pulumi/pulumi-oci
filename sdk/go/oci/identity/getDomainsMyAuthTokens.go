// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of My Auth Tokens in Oracle Cloud Infrastructure Identity Domains service.
//
// # Search AuthTokens
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
//			_, err := Identity.GetDomainsMyAuthTokens(ctx, &identity.GetDomainsMyAuthTokensArgs{
//				IdcsEndpoint:              data.Oci_identity_domain.Test_domain.Url,
//				MyAuthTokenCount:          pulumi.IntRef(_var.My_auth_token_my_auth_token_count),
//				MyAuthTokenFilter:         pulumi.StringRef(_var.My_auth_token_my_auth_token_filter),
//				Authorization:             pulumi.StringRef(_var.My_auth_token_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.My_auth_token_resource_type_schema_version),
//				StartIndex:                pulumi.IntRef(_var.My_auth_token_start_index),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDomainsMyAuthTokens(ctx *pulumi.Context, args *GetDomainsMyAuthTokensArgs, opts ...pulumi.InvokeOption) (*GetDomainsMyAuthTokensResult, error) {
	var rv GetDomainsMyAuthTokensResult
	err := ctx.Invoke("oci:Identity/getDomainsMyAuthTokens:getDomainsMyAuthTokens", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsMyAuthTokens.
type GetDomainsMyAuthTokensArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	MyAuthTokenCount *int `pulumi:"myAuthTokenCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	MyAuthTokenFilter *string `pulumi:"myAuthTokenFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    *string `pulumi:"sortBy"`
	SortOrder                 *string `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex *int `pulumi:"startIndex"`
}

// A collection of values returned by getDomainsMyAuthTokens.
type GetDomainsMyAuthTokensResult struct {
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id                string  `pulumi:"id"`
	IdcsEndpoint      string  `pulumi:"idcsEndpoint"`
	ItemsPerPage      int     `pulumi:"itemsPerPage"`
	MyAuthTokenCount  *int    `pulumi:"myAuthTokenCount"`
	MyAuthTokenFilter *string `pulumi:"myAuthTokenFilter"`
	// The list of my_auth_tokens.
	MyAuthTokens              []GetDomainsMyAuthTokensMyAuthToken `pulumi:"myAuthTokens"`
	ResourceTypeSchemaVersion *string                             `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas      []string `pulumi:"schemas"`
	SortBy       *string  `pulumi:"sortBy"`
	SortOrder    *string  `pulumi:"sortOrder"`
	StartIndex   *int     `pulumi:"startIndex"`
	TotalResults int      `pulumi:"totalResults"`
}

func GetDomainsMyAuthTokensOutput(ctx *pulumi.Context, args GetDomainsMyAuthTokensOutputArgs, opts ...pulumi.InvokeOption) GetDomainsMyAuthTokensResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDomainsMyAuthTokensResult, error) {
			args := v.(GetDomainsMyAuthTokensArgs)
			r, err := GetDomainsMyAuthTokens(ctx, &args, opts...)
			var s GetDomainsMyAuthTokensResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDomainsMyAuthTokensResultOutput)
}

// A collection of arguments for invoking getDomainsMyAuthTokens.
type GetDomainsMyAuthTokensOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	MyAuthTokenCount pulumi.IntPtrInput `pulumi:"myAuthTokenCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	MyAuthTokenFilter pulumi.StringPtrInput `pulumi:"myAuthTokenFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    pulumi.StringPtrInput `pulumi:"sortBy"`
	SortOrder                 pulumi.StringPtrInput `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex pulumi.IntPtrInput `pulumi:"startIndex"`
}

func (GetDomainsMyAuthTokensOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsMyAuthTokensArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsMyAuthTokens.
type GetDomainsMyAuthTokensResultOutput struct{ *pulumi.OutputState }

func (GetDomainsMyAuthTokensResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsMyAuthTokensResult)(nil)).Elem()
}

func (o GetDomainsMyAuthTokensResultOutput) ToGetDomainsMyAuthTokensResultOutput() GetDomainsMyAuthTokensResultOutput {
	return o
}

func (o GetDomainsMyAuthTokensResultOutput) ToGetDomainsMyAuthTokensResultOutputWithContext(ctx context.Context) GetDomainsMyAuthTokensResultOutput {
	return o
}

func (o GetDomainsMyAuthTokensResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDomainsMyAuthTokensResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) ItemsPerPage() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) int { return v.ItemsPerPage }).(pulumi.IntOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) MyAuthTokenCount() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *int { return v.MyAuthTokenCount }).(pulumi.IntPtrOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) MyAuthTokenFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.MyAuthTokenFilter }).(pulumi.StringPtrOutput)
}

// The list of my_auth_tokens.
func (o GetDomainsMyAuthTokensResultOutput) MyAuthTokens() GetDomainsMyAuthTokensMyAuthTokenArrayOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) []GetDomainsMyAuthTokensMyAuthToken { return v.MyAuthTokens }).(GetDomainsMyAuthTokensMyAuthTokenArrayOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o GetDomainsMyAuthTokensResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) SortBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.SortBy }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) SortOrder() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *string { return v.SortOrder }).(pulumi.StringPtrOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) StartIndex() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) *int { return v.StartIndex }).(pulumi.IntPtrOutput)
}

func (o GetDomainsMyAuthTokensResultOutput) TotalResults() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsMyAuthTokensResult) int { return v.TotalResults }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDomainsMyAuthTokensResultOutput{})
}