// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Data Safe Private Endpoints in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of Data Safe private endpoints.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetDataSafePrivateEndpoints(ctx, &datasafe.GetDataSafePrivateEndpointsArgs{
//				CompartmentId:          compartmentId,
//				AccessLevel:            pulumi.StringRef(dataSafePrivateEndpointAccessLevel),
//				CompartmentIdInSubtree: pulumi.BoolRef(dataSafePrivateEndpointCompartmentIdInSubtree),
//				DisplayName:            pulumi.StringRef(dataSafePrivateEndpointDisplayName),
//				State:                  pulumi.StringRef(dataSafePrivateEndpointState),
//				VcnId:                  pulumi.StringRef(testVcn.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDataSafePrivateEndpoints(ctx *pulumi.Context, args *GetDataSafePrivateEndpointsArgs, opts ...pulumi.InvokeOption) (*GetDataSafePrivateEndpointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDataSafePrivateEndpointsResult
	err := ctx.Invoke("oci:DataSafe/getDataSafePrivateEndpoints:getDataSafePrivateEndpoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDataSafePrivateEndpoints.
type GetDataSafePrivateEndpointsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName *string                             `pulumi:"displayName"`
	Filters     []GetDataSafePrivateEndpointsFilter `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state.
	State *string `pulumi:"state"`
	// A filter to return only resources that match the specified VCN OCID.
	VcnId *string `pulumi:"vcnId"`
}

// A collection of values returned by getDataSafePrivateEndpoints.
type GetDataSafePrivateEndpointsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The list of data_safe_private_endpoints.
	DataSafePrivateEndpoints []GetDataSafePrivateEndpointsDataSafePrivateEndpoint `pulumi:"dataSafePrivateEndpoints"`
	// The display name of the private endpoint.
	DisplayName *string                             `pulumi:"displayName"`
	Filters     []GetDataSafePrivateEndpointsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the private endpoint.
	State *string `pulumi:"state"`
	// The OCID of the VCN.
	VcnId *string `pulumi:"vcnId"`
}

func GetDataSafePrivateEndpointsOutput(ctx *pulumi.Context, args GetDataSafePrivateEndpointsOutputArgs, opts ...pulumi.InvokeOption) GetDataSafePrivateEndpointsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDataSafePrivateEndpointsResultOutput, error) {
			args := v.(GetDataSafePrivateEndpointsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getDataSafePrivateEndpoints:getDataSafePrivateEndpoints", args, GetDataSafePrivateEndpointsResultOutput{}, options).(GetDataSafePrivateEndpointsResultOutput), nil
		}).(GetDataSafePrivateEndpointsResultOutput)
}

// A collection of arguments for invoking getDataSafePrivateEndpoints.
type GetDataSafePrivateEndpointsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName pulumi.StringPtrInput                       `pulumi:"displayName"`
	Filters     GetDataSafePrivateEndpointsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the specified lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only resources that match the specified VCN OCID.
	VcnId pulumi.StringPtrInput `pulumi:"vcnId"`
}

func (GetDataSafePrivateEndpointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDataSafePrivateEndpointsArgs)(nil)).Elem()
}

// A collection of values returned by getDataSafePrivateEndpoints.
type GetDataSafePrivateEndpointsResultOutput struct{ *pulumi.OutputState }

func (GetDataSafePrivateEndpointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDataSafePrivateEndpointsResult)(nil)).Elem()
}

func (o GetDataSafePrivateEndpointsResultOutput) ToGetDataSafePrivateEndpointsResultOutput() GetDataSafePrivateEndpointsResultOutput {
	return o
}

func (o GetDataSafePrivateEndpointsResultOutput) ToGetDataSafePrivateEndpointsResultOutputWithContext(ctx context.Context) GetDataSafePrivateEndpointsResultOutput {
	return o
}

func (o GetDataSafePrivateEndpointsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment.
func (o GetDataSafePrivateEndpointsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetDataSafePrivateEndpointsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The list of data_safe_private_endpoints.
func (o GetDataSafePrivateEndpointsResultOutput) DataSafePrivateEndpoints() GetDataSafePrivateEndpointsDataSafePrivateEndpointArrayOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) []GetDataSafePrivateEndpointsDataSafePrivateEndpoint {
		return v.DataSafePrivateEndpoints
	}).(GetDataSafePrivateEndpointsDataSafePrivateEndpointArrayOutput)
}

// The display name of the private endpoint.
func (o GetDataSafePrivateEndpointsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDataSafePrivateEndpointsResultOutput) Filters() GetDataSafePrivateEndpointsFilterArrayOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) []GetDataSafePrivateEndpointsFilter { return v.Filters }).(GetDataSafePrivateEndpointsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDataSafePrivateEndpointsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the private endpoint.
func (o GetDataSafePrivateEndpointsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The OCID of the VCN.
func (o GetDataSafePrivateEndpointsResultOutput) VcnId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDataSafePrivateEndpointsResult) *string { return v.VcnId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDataSafePrivateEndpointsResultOutput{})
}
