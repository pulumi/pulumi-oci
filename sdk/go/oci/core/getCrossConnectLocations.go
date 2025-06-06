// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cross Connect Locations in Oracle Cloud Infrastructure Core service.
//
// Lists the available FastConnect locations for cross-connect installation. You need
// this information so you can specify your desired location when you create a cross-connect.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetCrossConnectLocations(ctx, &core.GetCrossConnectLocationsArgs{
//				CompartmentId: compartmentId,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCrossConnectLocations(ctx *pulumi.Context, args *GetCrossConnectLocationsArgs, opts ...pulumi.InvokeOption) (*GetCrossConnectLocationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCrossConnectLocationsResult
	err := ctx.Invoke("oci:Core/getCrossConnectLocations:getCrossConnectLocations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCrossConnectLocations.
type GetCrossConnectLocationsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                           `pulumi:"compartmentId"`
	Filters       []GetCrossConnectLocationsFilter `pulumi:"filters"`
}

// A collection of values returned by getCrossConnectLocations.
type GetCrossConnectLocationsResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The list of cross_connect_locations.
	CrossConnectLocations []GetCrossConnectLocationsCrossConnectLocation `pulumi:"crossConnectLocations"`
	Filters               []GetCrossConnectLocationsFilter               `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetCrossConnectLocationsOutput(ctx *pulumi.Context, args GetCrossConnectLocationsOutputArgs, opts ...pulumi.InvokeOption) GetCrossConnectLocationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCrossConnectLocationsResultOutput, error) {
			args := v.(GetCrossConnectLocationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getCrossConnectLocations:getCrossConnectLocations", args, GetCrossConnectLocationsResultOutput{}, options).(GetCrossConnectLocationsResultOutput), nil
		}).(GetCrossConnectLocationsResultOutput)
}

// A collection of arguments for invoking getCrossConnectLocations.
type GetCrossConnectLocationsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput                       `pulumi:"compartmentId"`
	Filters       GetCrossConnectLocationsFilterArrayInput `pulumi:"filters"`
}

func (GetCrossConnectLocationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectLocationsArgs)(nil)).Elem()
}

// A collection of values returned by getCrossConnectLocations.
type GetCrossConnectLocationsResultOutput struct{ *pulumi.OutputState }

func (GetCrossConnectLocationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectLocationsResult)(nil)).Elem()
}

func (o GetCrossConnectLocationsResultOutput) ToGetCrossConnectLocationsResultOutput() GetCrossConnectLocationsResultOutput {
	return o
}

func (o GetCrossConnectLocationsResultOutput) ToGetCrossConnectLocationsResultOutputWithContext(ctx context.Context) GetCrossConnectLocationsResultOutput {
	return o
}

func (o GetCrossConnectLocationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectLocationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of cross_connect_locations.
func (o GetCrossConnectLocationsResultOutput) CrossConnectLocations() GetCrossConnectLocationsCrossConnectLocationArrayOutput {
	return o.ApplyT(func(v GetCrossConnectLocationsResult) []GetCrossConnectLocationsCrossConnectLocation {
		return v.CrossConnectLocations
	}).(GetCrossConnectLocationsCrossConnectLocationArrayOutput)
}

func (o GetCrossConnectLocationsResultOutput) Filters() GetCrossConnectLocationsFilterArrayOutput {
	return o.ApplyT(func(v GetCrossConnectLocationsResult) []GetCrossConnectLocationsFilter { return v.Filters }).(GetCrossConnectLocationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCrossConnectLocationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectLocationsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCrossConnectLocationsResultOutput{})
}
