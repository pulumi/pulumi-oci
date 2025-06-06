// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of O Auth Partner Certificates in Oracle Cloud Infrastructure Identity Domains service.
//
// # Search OAuth Partner Certificates
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
//			_, err := identity.GetDomainsOauthPartnerCertificates(ctx, &identity.GetDomainsOauthPartnerCertificatesArgs{
//				IdcsEndpoint:                  testDomain.Url,
//				OauthPartnerCertificateCount:  pulumi.IntRef(oauthPartnerCertificateOauthPartnerCertificateCount),
//				OauthPartnerCertificateFilter: pulumi.StringRef(oauthPartnerCertificateOauthPartnerCertificateFilter),
//				Authorization:                 pulumi.StringRef(oauthPartnerCertificateAuthorization),
//				ResourceTypeSchemaVersion:     pulumi.StringRef(oauthPartnerCertificateResourceTypeSchemaVersion),
//				StartIndex:                    pulumi.IntRef(oauthPartnerCertificateStartIndex),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDomainsOauthPartnerCertificates(ctx *pulumi.Context, args *GetDomainsOauthPartnerCertificatesArgs, opts ...pulumi.InvokeOption) (*GetDomainsOauthPartnerCertificatesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDomainsOauthPartnerCertificatesResult
	err := ctx.Invoke("oci:Identity/getDomainsOauthPartnerCertificates:getDomainsOauthPartnerCertificates", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsOauthPartnerCertificates.
type GetDomainsOauthPartnerCertificatesArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	OauthPartnerCertificateCount *int `pulumi:"oauthPartnerCertificateCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	OauthPartnerCertificateFilter *string `pulumi:"oauthPartnerCertificateFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    *string `pulumi:"sortBy"`
	SortOrder                 *string `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex *int `pulumi:"startIndex"`
}

// A collection of values returned by getDomainsOauthPartnerCertificates.
type GetDomainsOauthPartnerCertificatesResult struct {
	Authorization *string `pulumi:"authorization"`
	CompartmentId *string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id                            string  `pulumi:"id"`
	IdcsEndpoint                  string  `pulumi:"idcsEndpoint"`
	ItemsPerPage                  int     `pulumi:"itemsPerPage"`
	OauthPartnerCertificateCount  *int    `pulumi:"oauthPartnerCertificateCount"`
	OauthPartnerCertificateFilter *string `pulumi:"oauthPartnerCertificateFilter"`
	// The list of oauth_partner_certificates.
	OauthPartnerCertificates  []GetDomainsOauthPartnerCertificatesOauthPartnerCertificate `pulumi:"oauthPartnerCertificates"`
	ResourceTypeSchemaVersion *string                                                     `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas      []string `pulumi:"schemas"`
	SortBy       *string  `pulumi:"sortBy"`
	SortOrder    *string  `pulumi:"sortOrder"`
	StartIndex   *int     `pulumi:"startIndex"`
	TotalResults int      `pulumi:"totalResults"`
}

func GetDomainsOauthPartnerCertificatesOutput(ctx *pulumi.Context, args GetDomainsOauthPartnerCertificatesOutputArgs, opts ...pulumi.InvokeOption) GetDomainsOauthPartnerCertificatesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDomainsOauthPartnerCertificatesResultOutput, error) {
			args := v.(GetDomainsOauthPartnerCertificatesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsOauthPartnerCertificates:getDomainsOauthPartnerCertificates", args, GetDomainsOauthPartnerCertificatesResultOutput{}, options).(GetDomainsOauthPartnerCertificatesResultOutput), nil
		}).(GetDomainsOauthPartnerCertificatesResultOutput)
}

// A collection of arguments for invoking getDomainsOauthPartnerCertificates.
type GetDomainsOauthPartnerCertificatesOutputArgs struct {
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
	OauthPartnerCertificateCount pulumi.IntPtrInput `pulumi:"oauthPartnerCertificateCount"`
	// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
	OauthPartnerCertificateFilter pulumi.StringPtrInput `pulumi:"oauthPartnerCertificateFilter"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
	SortBy                    pulumi.StringPtrInput `pulumi:"sortBy"`
	SortOrder                 pulumi.StringPtrInput `pulumi:"sortOrder"`
	// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
	StartIndex pulumi.IntPtrInput `pulumi:"startIndex"`
}

func (GetDomainsOauthPartnerCertificatesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsOauthPartnerCertificatesArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsOauthPartnerCertificates.
type GetDomainsOauthPartnerCertificatesResultOutput struct{ *pulumi.OutputState }

func (GetDomainsOauthPartnerCertificatesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsOauthPartnerCertificatesResult)(nil)).Elem()
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) ToGetDomainsOauthPartnerCertificatesResultOutput() GetDomainsOauthPartnerCertificatesResultOutput {
	return o
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) ToGetDomainsOauthPartnerCertificatesResultOutputWithContext(ctx context.Context) GetDomainsOauthPartnerCertificatesResultOutput {
	return o
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDomainsOauthPartnerCertificatesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) ItemsPerPage() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) int { return v.ItemsPerPage }).(pulumi.IntOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) OauthPartnerCertificateCount() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *int { return v.OauthPartnerCertificateCount }).(pulumi.IntPtrOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) OauthPartnerCertificateFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.OauthPartnerCertificateFilter }).(pulumi.StringPtrOutput)
}

// The list of oauth_partner_certificates.
func (o GetDomainsOauthPartnerCertificatesResultOutput) OauthPartnerCertificates() GetDomainsOauthPartnerCertificatesOauthPartnerCertificateArrayOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) []GetDomainsOauthPartnerCertificatesOauthPartnerCertificate {
		return v.OauthPartnerCertificates
	}).(GetDomainsOauthPartnerCertificatesOauthPartnerCertificateArrayOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o GetDomainsOauthPartnerCertificatesResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) SortBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.SortBy }).(pulumi.StringPtrOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) SortOrder() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *string { return v.SortOrder }).(pulumi.StringPtrOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) StartIndex() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) *int { return v.StartIndex }).(pulumi.IntPtrOutput)
}

func (o GetDomainsOauthPartnerCertificatesResultOutput) TotalResults() pulumi.IntOutput {
	return o.ApplyT(func(v GetDomainsOauthPartnerCertificatesResult) int { return v.TotalResults }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDomainsOauthPartnerCertificatesResultOutput{})
}
