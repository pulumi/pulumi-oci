// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Regions in Oracle Cloud Infrastructure Identity service.
//
// Lists all the regions offered by Oracle Cloud Infrastructure.
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
//			_, err := identity.GetRegions(ctx, &identity.GetRegionsArgs{}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRegions(ctx *pulumi.Context, args *GetRegionsArgs, opts ...pulumi.InvokeOption) (*GetRegionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRegionsResult
	err := ctx.Invoke("oci:Identity/getRegions:getRegions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRegions.
type GetRegionsArgs struct {
	Filters []GetRegionsFilter `pulumi:"filters"`
}

// A collection of values returned by getRegions.
type GetRegionsResult struct {
	Filters []GetRegionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of regions.
	Regions []GetRegionsRegion `pulumi:"regions"`
}

func GetRegionsOutput(ctx *pulumi.Context, args GetRegionsOutputArgs, opts ...pulumi.InvokeOption) GetRegionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetRegionsResultOutput, error) {
			args := v.(GetRegionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getRegions:getRegions", args, GetRegionsResultOutput{}, options).(GetRegionsResultOutput), nil
		}).(GetRegionsResultOutput)
}

// A collection of arguments for invoking getRegions.
type GetRegionsOutputArgs struct {
	Filters GetRegionsFilterArrayInput `pulumi:"filters"`
}

func (GetRegionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRegionsArgs)(nil)).Elem()
}

// A collection of values returned by getRegions.
type GetRegionsResultOutput struct{ *pulumi.OutputState }

func (GetRegionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRegionsResult)(nil)).Elem()
}

func (o GetRegionsResultOutput) ToGetRegionsResultOutput() GetRegionsResultOutput {
	return o
}

func (o GetRegionsResultOutput) ToGetRegionsResultOutputWithContext(ctx context.Context) GetRegionsResultOutput {
	return o
}

func (o GetRegionsResultOutput) Filters() GetRegionsFilterArrayOutput {
	return o.ApplyT(func(v GetRegionsResult) []GetRegionsFilter { return v.Filters }).(GetRegionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRegionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRegionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of regions.
func (o GetRegionsResultOutput) Regions() GetRegionsRegionArrayOutput {
	return o.ApplyT(func(v GetRegionsResult) []GetRegionsRegion { return v.Regions }).(GetRegionsRegionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRegionsResultOutput{})
}
