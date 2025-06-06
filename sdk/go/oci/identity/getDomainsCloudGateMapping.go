// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Cloud Gate Mapping resource in Oracle Cloud Infrastructure Identity Domains service.
//
// # Get a Cloud Gate mapping
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
//			_, err := identity.GetDomainsCloudGateMapping(ctx, &identity.GetDomainsCloudGateMappingArgs{
//				CloudGateMappingId: testCloudGateMappingOciIdentityDomainsCloudGateMapping.Id,
//				IdcsEndpoint:       testDomain.Url,
//				AttributeSets: []string{
//					"all",
//				},
//				Attributes:                pulumi.StringRef(""),
//				Authorization:             pulumi.StringRef(cloudGateMappingAuthorization),
//				ResourceTypeSchemaVersion: pulumi.StringRef(cloudGateMappingResourceTypeSchemaVersion),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDomainsCloudGateMapping(ctx *pulumi.Context, args *LookupDomainsCloudGateMappingArgs, opts ...pulumi.InvokeOption) (*LookupDomainsCloudGateMappingResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDomainsCloudGateMappingResult
	err := ctx.Invoke("oci:Identity/getDomainsCloudGateMapping:getDomainsCloudGateMapping", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomainsCloudGateMapping.
type LookupDomainsCloudGateMappingArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets []string `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes *string `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization *string `pulumi:"authorization"`
	// ID of the resource
	CloudGateMappingId string `pulumi:"cloudGateMappingId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint string `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
}

// A collection of values returned by getDomainsCloudGateMapping.
type LookupDomainsCloudGateMappingResult struct {
	AttributeSets      []string `pulumi:"attributeSets"`
	Attributes         *string  `pulumi:"attributes"`
	Authorization      *string  `pulumi:"authorization"`
	CloudGateMappingId string   `pulumi:"cloudGateMappingId"`
	// Reference to owning Cloud Gate
	CloudGates []GetDomainsCloudGateMappingCloudGate `pulumi:"cloudGates"`
	// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
	CompartmentOcid string `pulumi:"compartmentOcid"`
	// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
	DeleteInProgress bool `pulumi:"deleteInProgress"`
	// Brief description for this Cloud Gate
	Description string `pulumi:"description"`
	// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
	DomainOcid string `pulumi:"domainOcid"`
	// Reference to gateway application protected by this Cloud Gate
	GatewayApps []GetDomainsCloudGateMappingGatewayApp `pulumi:"gatewayApps"`
	// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
	Id string `pulumi:"id"`
	// The User or App who created the Resource
	IdcsCreatedBies []GetDomainsCloudGateMappingIdcsCreatedBy `pulumi:"idcsCreatedBies"`
	IdcsEndpoint    string                                    `pulumi:"idcsEndpoint"`
	// The User or App who modified the Resource
	IdcsLastModifiedBies []GetDomainsCloudGateMappingIdcsLastModifiedBy `pulumi:"idcsLastModifiedBies"`
	// The release number when the resource was upgraded.
	IdcsLastUpgradedInRelease string `pulumi:"idcsLastUpgradedInRelease"`
	// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
	IdcsPreventedOperations []string `pulumi:"idcsPreventedOperations"`
	// Indicates whether this resource was created by OPC
	IsOpcService bool `pulumi:"isOpcService"`
	// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
	Metas []GetDomainsCloudGateMappingMeta `pulumi:"metas"`
	// More NGINX Settings. JSON encoded key value pairs similar to WTP encoding
	NginxSettings string `pulumi:"nginxSettings"`
	// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
	Ocid string `pulumi:"ocid"`
	// The Web Tier policy name used for the App that is mapped to the owning Cloud Gate
	PolicyName string `pulumi:"policyName"`
	// NGINX ProxyPass entry for this Mapping
	ProxyPass string `pulumi:"proxyPass"`
	// Resource prefix for this mapping.  This will be used to define the location block
	ResourcePrefix            string  `pulumi:"resourcePrefix"`
	ResourceTypeSchemaVersion *string `pulumi:"resourceTypeSchemaVersion"`
	// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
	Schemas []string `pulumi:"schemas"`
	// Reference to server block for this mapping
	Servers []GetDomainsCloudGateMappingServer `pulumi:"servers"`
	// A list of tags on this resource.
	Tags []GetDomainsCloudGateMappingTag `pulumi:"tags"`
	// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
	TenancyOcid string `pulumi:"tenancyOcid"`
	// Reference to upstream block for this mapping
	UpstreamServerGroups []GetDomainsCloudGateMappingUpstreamServerGroup `pulumi:"upstreamServerGroups"`
}

func LookupDomainsCloudGateMappingOutput(ctx *pulumi.Context, args LookupDomainsCloudGateMappingOutputArgs, opts ...pulumi.InvokeOption) LookupDomainsCloudGateMappingResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDomainsCloudGateMappingResultOutput, error) {
			args := v.(LookupDomainsCloudGateMappingArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getDomainsCloudGateMapping:getDomainsCloudGateMapping", args, LookupDomainsCloudGateMappingResultOutput{}, options).(LookupDomainsCloudGateMappingResultOutput), nil
		}).(LookupDomainsCloudGateMappingResultOutput)
}

// A collection of arguments for invoking getDomainsCloudGateMapping.
type LookupDomainsCloudGateMappingOutputArgs struct {
	// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
	AttributeSets pulumi.StringArrayInput `pulumi:"attributeSets"`
	// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
	Attributes pulumi.StringPtrInput `pulumi:"attributes"`
	// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
	Authorization pulumi.StringPtrInput `pulumi:"authorization"`
	// ID of the resource
	CloudGateMappingId pulumi.StringInput `pulumi:"cloudGateMappingId"`
	// The basic endpoint for the identity domain
	IdcsEndpoint pulumi.StringInput `pulumi:"idcsEndpoint"`
	// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
	ResourceTypeSchemaVersion pulumi.StringPtrInput `pulumi:"resourceTypeSchemaVersion"`
}

func (LookupDomainsCloudGateMappingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsCloudGateMappingArgs)(nil)).Elem()
}

// A collection of values returned by getDomainsCloudGateMapping.
type LookupDomainsCloudGateMappingResultOutput struct{ *pulumi.OutputState }

func (LookupDomainsCloudGateMappingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDomainsCloudGateMappingResult)(nil)).Elem()
}

func (o LookupDomainsCloudGateMappingResultOutput) ToLookupDomainsCloudGateMappingResultOutput() LookupDomainsCloudGateMappingResultOutput {
	return o
}

func (o LookupDomainsCloudGateMappingResultOutput) ToLookupDomainsCloudGateMappingResultOutputWithContext(ctx context.Context) LookupDomainsCloudGateMappingResultOutput {
	return o
}

func (o LookupDomainsCloudGateMappingResultOutput) AttributeSets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []string { return v.AttributeSets }).(pulumi.StringArrayOutput)
}

func (o LookupDomainsCloudGateMappingResultOutput) Attributes() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) *string { return v.Attributes }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsCloudGateMappingResultOutput) Authorization() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) *string { return v.Authorization }).(pulumi.StringPtrOutput)
}

func (o LookupDomainsCloudGateMappingResultOutput) CloudGateMappingId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.CloudGateMappingId }).(pulumi.StringOutput)
}

// Reference to owning Cloud Gate
func (o LookupDomainsCloudGateMappingResultOutput) CloudGates() GetDomainsCloudGateMappingCloudGateArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingCloudGate { return v.CloudGates }).(GetDomainsCloudGateMappingCloudGateArrayOutput)
}

// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
func (o LookupDomainsCloudGateMappingResultOutput) CompartmentOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.CompartmentOcid }).(pulumi.StringOutput)
}

// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
func (o LookupDomainsCloudGateMappingResultOutput) DeleteInProgress() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) bool { return v.DeleteInProgress }).(pulumi.BoolOutput)
}

// Brief description for this Cloud Gate
func (o LookupDomainsCloudGateMappingResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.Description }).(pulumi.StringOutput)
}

// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
func (o LookupDomainsCloudGateMappingResultOutput) DomainOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.DomainOcid }).(pulumi.StringOutput)
}

// Reference to gateway application protected by this Cloud Gate
func (o LookupDomainsCloudGateMappingResultOutput) GatewayApps() GetDomainsCloudGateMappingGatewayAppArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingGatewayApp {
		return v.GatewayApps
	}).(GetDomainsCloudGateMappingGatewayAppArrayOutput)
}

// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
func (o LookupDomainsCloudGateMappingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.Id }).(pulumi.StringOutput)
}

// The User or App who created the Resource
func (o LookupDomainsCloudGateMappingResultOutput) IdcsCreatedBies() GetDomainsCloudGateMappingIdcsCreatedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingIdcsCreatedBy {
		return v.IdcsCreatedBies
	}).(GetDomainsCloudGateMappingIdcsCreatedByArrayOutput)
}

func (o LookupDomainsCloudGateMappingResultOutput) IdcsEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.IdcsEndpoint }).(pulumi.StringOutput)
}

// The User or App who modified the Resource
func (o LookupDomainsCloudGateMappingResultOutput) IdcsLastModifiedBies() GetDomainsCloudGateMappingIdcsLastModifiedByArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingIdcsLastModifiedBy {
		return v.IdcsLastModifiedBies
	}).(GetDomainsCloudGateMappingIdcsLastModifiedByArrayOutput)
}

// The release number when the resource was upgraded.
func (o LookupDomainsCloudGateMappingResultOutput) IdcsLastUpgradedInRelease() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.IdcsLastUpgradedInRelease }).(pulumi.StringOutput)
}

// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
func (o LookupDomainsCloudGateMappingResultOutput) IdcsPreventedOperations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []string { return v.IdcsPreventedOperations }).(pulumi.StringArrayOutput)
}

// Indicates whether this resource was created by OPC
func (o LookupDomainsCloudGateMappingResultOutput) IsOpcService() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) bool { return v.IsOpcService }).(pulumi.BoolOutput)
}

// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
func (o LookupDomainsCloudGateMappingResultOutput) Metas() GetDomainsCloudGateMappingMetaArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingMeta { return v.Metas }).(GetDomainsCloudGateMappingMetaArrayOutput)
}

// More NGINX Settings. JSON encoded key value pairs similar to WTP encoding
func (o LookupDomainsCloudGateMappingResultOutput) NginxSettings() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.NginxSettings }).(pulumi.StringOutput)
}

// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
func (o LookupDomainsCloudGateMappingResultOutput) Ocid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.Ocid }).(pulumi.StringOutput)
}

// The Web Tier policy name used for the App that is mapped to the owning Cloud Gate
func (o LookupDomainsCloudGateMappingResultOutput) PolicyName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.PolicyName }).(pulumi.StringOutput)
}

// NGINX ProxyPass entry for this Mapping
func (o LookupDomainsCloudGateMappingResultOutput) ProxyPass() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.ProxyPass }).(pulumi.StringOutput)
}

// Resource prefix for this mapping.  This will be used to define the location block
func (o LookupDomainsCloudGateMappingResultOutput) ResourcePrefix() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.ResourcePrefix }).(pulumi.StringOutput)
}

func (o LookupDomainsCloudGateMappingResultOutput) ResourceTypeSchemaVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) *string { return v.ResourceTypeSchemaVersion }).(pulumi.StringPtrOutput)
}

// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
func (o LookupDomainsCloudGateMappingResultOutput) Schemas() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []string { return v.Schemas }).(pulumi.StringArrayOutput)
}

// Reference to server block for this mapping
func (o LookupDomainsCloudGateMappingResultOutput) Servers() GetDomainsCloudGateMappingServerArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingServer { return v.Servers }).(GetDomainsCloudGateMappingServerArrayOutput)
}

// A list of tags on this resource.
func (o LookupDomainsCloudGateMappingResultOutput) Tags() GetDomainsCloudGateMappingTagArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingTag { return v.Tags }).(GetDomainsCloudGateMappingTagArrayOutput)
}

// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
func (o LookupDomainsCloudGateMappingResultOutput) TenancyOcid() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) string { return v.TenancyOcid }).(pulumi.StringOutput)
}

// Reference to upstream block for this mapping
func (o LookupDomainsCloudGateMappingResultOutput) UpstreamServerGroups() GetDomainsCloudGateMappingUpstreamServerGroupArrayOutput {
	return o.ApplyT(func(v LookupDomainsCloudGateMappingResult) []GetDomainsCloudGateMappingUpstreamServerGroup {
		return v.UpstreamServerGroups
	}).(GetDomainsCloudGateMappingUpstreamServerGroupArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDomainsCloudGateMappingResultOutput{})
}
