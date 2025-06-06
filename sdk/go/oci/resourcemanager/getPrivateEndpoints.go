// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package resourcemanager

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Private Endpoints in Oracle Cloud Infrastructure Resource Manager service.
//
// Lists private endpoints according to the specified filter.
// - For `compartmentId`, lists all private endpoint in the matching compartment.
// - For `privateEndpointId`, lists the matching private endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/resourcemanager"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := resourcemanager.GetPrivateEndpoints(ctx, &resourcemanager.GetPrivateEndpointsArgs{
//				CompartmentId:     pulumi.StringRef(compartmentId),
//				DisplayName:       pulumi.StringRef(privateEndpointDisplayName),
//				PrivateEndpointId: pulumi.StringRef(testPrivateEndpoint.Id),
//				VcnId:             pulumi.StringRef(testVcn.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPrivateEndpoints(ctx *pulumi.Context, args *GetPrivateEndpointsArgs, opts ...pulumi.InvokeOption) (*GetPrivateEndpointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetPrivateEndpointsResult
	err := ctx.Invoke("oci:ResourceManager/getPrivateEndpoints:getPrivateEndpoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPrivateEndpoints.
type GetPrivateEndpointsArgs struct {
	// A filter to return only resources that exist in the compartment, identified by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list a resource by name. Requires `sortBy` set to `DISPLAYNAME`. Alternatively, when you know the resource OCID, use the related Get operation.
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetPrivateEndpointsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
	PrivateEndpointId *string `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId *string `pulumi:"vcnId"`
}

// A collection of values returned by getPrivateEndpoints.
type GetPrivateEndpointsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                     `pulumi:"displayName"`
	Filters     []GetPrivateEndpointsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of private_endpoint_collection.
	PrivateEndpointCollections []GetPrivateEndpointsPrivateEndpointCollection `pulumi:"privateEndpointCollections"`
	PrivateEndpointId          *string                                        `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
	VcnId *string `pulumi:"vcnId"`
}

func GetPrivateEndpointsOutput(ctx *pulumi.Context, args GetPrivateEndpointsOutputArgs, opts ...pulumi.InvokeOption) GetPrivateEndpointsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetPrivateEndpointsResultOutput, error) {
			args := v.(GetPrivateEndpointsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ResourceManager/getPrivateEndpoints:getPrivateEndpoints", args, GetPrivateEndpointsResultOutput{}, options).(GetPrivateEndpointsResultOutput), nil
		}).(GetPrivateEndpointsResultOutput)
}

// A collection of arguments for invoking getPrivateEndpoints.
type GetPrivateEndpointsOutputArgs struct {
	// A filter to return only resources that exist in the compartment, identified by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list a resource by name. Requires `sortBy` set to `DISPLAYNAME`. Alternatively, when you know the resource OCID, use the related Get operation.
	DisplayName pulumi.StringPtrInput               `pulumi:"displayName"`
	Filters     GetPrivateEndpointsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
	PrivateEndpointId pulumi.StringPtrInput `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringPtrInput `pulumi:"vcnId"`
}

func (GetPrivateEndpointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPrivateEndpointsArgs)(nil)).Elem()
}

// A collection of values returned by getPrivateEndpoints.
type GetPrivateEndpointsResultOutput struct{ *pulumi.OutputState }

func (GetPrivateEndpointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPrivateEndpointsResult)(nil)).Elem()
}

func (o GetPrivateEndpointsResultOutput) ToGetPrivateEndpointsResultOutput() GetPrivateEndpointsResultOutput {
	return o
}

func (o GetPrivateEndpointsResultOutput) ToGetPrivateEndpointsResultOutputWithContext(ctx context.Context) GetPrivateEndpointsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
func (o GetPrivateEndpointsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetPrivateEndpointsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetPrivateEndpointsResultOutput) Filters() GetPrivateEndpointsFilterArrayOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) []GetPrivateEndpointsFilter { return v.Filters }).(GetPrivateEndpointsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPrivateEndpointsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of private_endpoint_collection.
func (o GetPrivateEndpointsResultOutput) PrivateEndpointCollections() GetPrivateEndpointsPrivateEndpointCollectionArrayOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) []GetPrivateEndpointsPrivateEndpointCollection {
		return v.PrivateEndpointCollections
	}).(GetPrivateEndpointsPrivateEndpointCollectionArrayOutput)
}

func (o GetPrivateEndpointsResultOutput) PrivateEndpointId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) *string { return v.PrivateEndpointId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
func (o GetPrivateEndpointsResultOutput) VcnId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPrivateEndpointsResult) *string { return v.VcnId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPrivateEndpointsResultOutput{})
}
