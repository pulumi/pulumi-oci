// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Groups in Oracle Cloud Infrastructure Identity Domains service.
//
// Search Groups.The Group search and get operations on users/members will throw an exception if it has more than 10K members, to avoid the exception use the pagination filter to get or search group members
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
//			_, err := Identity.GetDomainsGroups(ctx, &identity.GetDomainsGroupsArgs{
//				IdcsEndpoint:              data.Oci_identity_domain.Test_domain.Url,
//				GroupCount:                pulumi.IntRef(_var.Group_group_count),
//				GroupFilter:               pulumi.StringRef(_var.Group_group_filter),
//				AttributeSets:             []interface{}{},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(_var.Group_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.Group_resource_type_schema_version),
//				StartIndex:                pulumi.IntRef(_var.Group_start_index),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDomainsGroups(ctx *pulumi.Context, args *GetDomainsGroupsArgs, opts ...pulumi.InvokeOption) (*GetDomainsGroupsResult, error) {
	var rv GetDomainsGroupsResult
	err := ctx.Invoke("oci:Identity/getDomainsGroups:getDomainsGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsGroups.
type GetDomainsGroupsArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	GroupCount *int `pulumi:"groupCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	GroupFilter *string `pulumi:"groupFilter"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    *string `pulumi:"sortBy"`
	SortOrder                 *string `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex *int `pulumi:"startIndex"`
}

// A collection of values returned by getDomainsGroups.
type GetDomainsGroupsResult struct {
	AttributeSets []string `pulumi:"attributeSets"`
	Attributes    *string  `pulumi:"attributes"`
	Authorization *string  `pulumi:"authorization"`
	CompartmentId *string  `pulumi:"compartmentId"`
	GroupCount    *int     `pulumi:"groupCount"`
	GroupFilter   *string  `pulumi:"groupFilter"`
	// The list of groups.
	Groups []GetDomainsGroupsGroup `pulumi:"groups"`
	// The provider-assigned unique ID for this managed resource.
	Id                        string  `pulumi:"id"`
	IdcsEndpoint              string  `pulumi:"idcsEndpoint"`
	ItemsPerPage              int     `pulumi:"itemsPerPage"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas      []string `pulumi:"schemas"`
	SortBy       *string  `pulumi:"sortBy"`
	SortOrder    *string  `pulumi:"sortOrder"`
	StartIndex   *int     `pulumi:"startIndex"`
	TotalResults int      `pulumi:"totalResults"`
}

func GetDomainsGroupsOutput(ctx *pulumi.Context, args GetDomainsGroupsOutputArgs, opts ...pulumi.InvokeOption) GetDomainsGroupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDomainsGroupsResult, error) {
			args := v.(GetDomainsGroupsArgs)
			r, err := GetDomainsGroups(ctx, &args, opts...)
			var s GetDomainsGroupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDomainsGroupsResultOutput)
}

// A collection of arguments for invoking getDomainsGroups.
type GetDomainsGroupsOutputArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	GroupCount pulumi.IntPtrInput `pulumi:"groupCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	GroupFilter pulumi.StringPtrInput `pulumi:"groupFilter"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    pulumi.StringPtrInput `pulumi:"sortBy"`
	SortOrder                 pulumi.StringPtrInput `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex pulumi.IntPtrInput `pulumi:"startIndex"`
}

func (GetDomainsGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsGroups.
type GetDomainsGroupsResultOutput struct{ *pulumi.OutputState }

func (GetDomainsGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsGroupsResult)(nil)).Elem()
}

func (o GetDomainsGroupsResultOutput) ToGetDomainsGroupsResultOutput() GetDomainsGroupsResultOutput {
	return o
}

func (o GetDomainsGroupsResultOutput) ToGetDomainsGroupsResultOutputWithContext(ctx context.Context) GetDomainsGroupsResultOutput {
	return o
}

func (o GetDomainsGroupsResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o GetDomainsGroupsResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o GetDomainsGroupsResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

func (o GetDomainsGroupsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetDomainsGroupsResultOutput) GroupCount() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *int { return v.GroupCount }).(pulumi.IntPtrOutput)
}

func (o GetDomainsGroupsResultOutput) GroupFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.GroupFilter }).(pulumi.StringPtrOutput)
}

// The list of groups.
func (o GetDomainsGroupsResultOutput) Groups() GetDomainsGroupsGroupArrayOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) []GetDomainsGroupsGroup { return v.Groups }).(GetDomainsGroupsGroupArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDomainsGroupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetDomainsGroupsResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

func (o GetDomainsGroupsResultOutput) ItemsPerPage() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) int { return v.ItemsPerPage }).(pulumi.IntOutput)
}

func (o GetDomainsGroupsResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o GetDomainsGroupsResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

func (o GetDomainsGroupsResultOutput) SortBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.SortBy }).(pulumi.StringPtrOutput)
}

func (o GetDomainsGroupsResultOutput) SortOrder() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *string { return v.SortOrder }).(pulumi.StringPtrOutput)
}

func (o GetDomainsGroupsResultOutput) StartIndex() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) *int { return v.StartIndex }).(pulumi.IntPtrOutput)
}

func (o GetDomainsGroupsResultOutput) TotalResults() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsGroupsResult) int { return v.TotalResults }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDomainsGroupsResultOutput{})
}