// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Auth Token resource in Oracle Cloud Infrastructure Identity Domains service.
//
// # Get user's auth token
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
//			_, err := Identity.GetDomainsAuthToken(ctx, &identity.GetDomainsAuthTokenArgs{
//				AuthTokenId:               oci_identity_auth_token.Test_auth_token.Id,
//				IdcsEndpoint:              data.Oci_identity_domain.Test_domain.Url,
//				AttributeSets:             []interface{}{},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(_var.Auth_token_authorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(_var.Auth_token_resource_type_schema_version),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsAuthToken(ctx *pulumi.Context, args *LookupDomainsAuthTokenArgs, opts ...pulumi.InvokeOption) (*LookupDomainsAuthTokenResult, error) {
	var rv LookupDomainsAuthTokenResult
	err := ctx.Invoke("oci:Identity/getDomainsAuthToken:getDomainsAuthToken", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsAuthToken.
type LookupDomainsAuthTokenArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// ID of the resource
	AuthTokenId string `pulumi:"authTokenId"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsAuthToken.
type LookupDomainsAuthTokenResult struct {
	AttributeSets []string `pulumi:"attributeSets"`
	Attributes    *string  `pulumi:"attributes"`
	AuthTokenId   string   `pulumi:"authTokenId"`
	Authorization *string  `pulumi:"authorization"`
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
	IdcsCreatedBies []GetDomainsAuthTokenIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                             `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsAuthTokenIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsAuthTokenMeta `pulumi:"metas"`
	// User's ocid
	Ocid                      string  `pulumi:"ocid"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// User credential status
	Status string `pulumi:"status"`
	// A list of tags on this resource.
	Tags []GetDomainsAuthTokenTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// Controls whether a user can update themselves or not via User related APIs
	UrnietfparamsscimschemasoracleidcsextensionselfChangeUsers []GetDomainsAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser `pulumi:"urnietfparamsscimschemasoracleidcsextensionselfChangeUsers"`
	// User linked to auth token
	Users []GetDomainsAuthTokenUser `pulumi:"users"`
}

func LookupDomainsAuthTokenOutput(ctx *pulumi.Context, args LookupDomainsAuthTokenOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsAuthTokenResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDomainsAuthTokenResult, error) {
			args := v.(LookupDomainsAuthTokenArgs)
			r, err := LookupDomainsAuthToken(ctx, &args, opts...)
			var s LookupDomainsAuthTokenResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDomainsAuthTokenResultOutput)
}

// A collection of arguments for invoking getDomainsAuthToken.
type LookupDomainsAuthTokenOutputArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// ID of the resource
	AuthTokenId pulumi.StringInput `pulumi:"authTokenId"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsAuthTokenOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsAuthTokenArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsAuthToken.
type LookupDomainsAuthTokenResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsAuthTokenResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsAuthTokenResult)(nil)).Elem()
}

func (o LookupDomainsAuthTokenResultOutput) ToLookupDomainsAuthTokenResultOutput() LookupDomainsAuthTokenResultOutput {
	return o
}

func (o LookupDomainsAuthTokenResultOutput) ToLookupDomainsAuthTokenResultOutputWithContext(ctx context.Context) LookupDomainsAuthTokenResultOutput {
	return o
}

func (o LookupDomainsAuthTokenResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsAuthTokenResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsAuthTokenResultOutput) AuthTokenId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.AuthTokenId }).(pulumi.StringOutput)
}

func (o LookupDomainsAuthTokenResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsAuthTokenResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsAuthTokenResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Description
func (o LookupDomainsAuthTokenResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.Description }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsAuthTokenResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// User credential expires on
func (o LookupDomainsAuthTokenResultOutput) ExpiresOn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.ExpiresOn }).(pulumi.StringOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsAuthTokenResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsAuthTokenResultOutput) IdcsCreatedBies() GetDomainsAuthTokenIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenIdcsCreatedBy { return v.IdcsCreatedBies }).(GetDomainsAuthTokenIdcsCreatedByArrayOutput)
}

func (o LookupDomainsAuthTokenResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsAuthTokenResultOutput) IdcsLastModifiedBies() GetDomainsAuthTokenIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsAuthTokenIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsAuthTokenResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsAuthTokenResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsAuthTokenResultOutput) Metas() GetDomainsAuthTokenMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenMeta { return v.Metas }).(GetDomainsAuthTokenMetaArrayOutput)
}

// User's ocid
func (o LookupDomainsAuthTokenResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.Ocid }).(pulumi.StringOutput)
}

func (o LookupDomainsAuthTokenResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsAuthTokenResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// User credential status
func (o LookupDomainsAuthTokenResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.Status }).(pulumi.StringOutput)
}

// A list of tags on this resource.
func (o LookupDomainsAuthTokenResultOutput) Tags() GetDomainsAuthTokenTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenTag { return v.Tags }).(GetDomainsAuthTokenTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsAuthTokenResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// Controls whether a user can update themselves or not via User related APIs
func (o LookupDomainsAuthTokenResultOutput) UrnietfparamsscimschemasoracleidcsextensionselfChangeUsers() GetDomainsAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser {
		return v.UrnietfparamsscimschemasoracleidcsextensionselfChangeUsers
	}).(GetDomainsAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArrayOutput)
}

// User linked to auth token
func (o LookupDomainsAuthTokenResultOutput) Users() GetDomainsAuthTokenUserArrayOutput {
	return o.ApplyT(func(v LookupDomainsAuthTokenResult) []GetDomainsAuthTokenUser { return v.Users }).(GetDomainsAuthTokenUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsAuthTokenResultOutput{})
}