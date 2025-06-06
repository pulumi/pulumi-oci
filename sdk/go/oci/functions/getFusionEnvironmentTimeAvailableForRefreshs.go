// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fusion Environment Time Available For Refreshs in Oracle Cloud Infrastructure Fusion Apps service.
//
// # Gets available refresh time for this fusion environment
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/functions"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := functions.GetFusionEnvironmentTimeAvailableForRefreshs(ctx, &functions.GetFusionEnvironmentTimeAvailableForRefreshsArgs{
//				FusionEnvironmentId: testFusionEnvironment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFusionEnvironmentTimeAvailableForRefreshs(ctx *pulumi.Context, args *GetFusionEnvironmentTimeAvailableForRefreshsArgs, opts ...pulumi.InvokeOption) (*GetFusionEnvironmentTimeAvailableForRefreshsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFusionEnvironmentTimeAvailableForRefreshsResult
	err := ctx.Invoke("oci:Functions/getFusionEnvironmentTimeAvailableForRefreshs:getFusionEnvironmentTimeAvailableForRefreshs", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFusionEnvironmentTimeAvailableForRefreshs.
type GetFusionEnvironmentTimeAvailableForRefreshsArgs struct {
	Filters []GetFusionEnvironmentTimeAvailableForRefreshsFilter `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
}

// A collection of values returned by getFusionEnvironmentTimeAvailableForRefreshs.
type GetFusionEnvironmentTimeAvailableForRefreshsResult struct {
	Filters             []GetFusionEnvironmentTimeAvailableForRefreshsFilter `pulumi:"filters"`
	FusionEnvironmentId string                                               `pulumi:"fusionEnvironmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of time_available_for_refresh_collection.
	TimeAvailableForRefreshCollections []GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollection `pulumi:"timeAvailableForRefreshCollections"`
}

func GetFusionEnvironmentTimeAvailableForRefreshsOutput(ctx *pulumi.Context, args GetFusionEnvironmentTimeAvailableForRefreshsOutputArgs, opts ...pulumi.InvokeOption) GetFusionEnvironmentTimeAvailableForRefreshsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFusionEnvironmentTimeAvailableForRefreshsResultOutput, error) {
			args := v.(GetFusionEnvironmentTimeAvailableForRefreshsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Functions/getFusionEnvironmentTimeAvailableForRefreshs:getFusionEnvironmentTimeAvailableForRefreshs", args, GetFusionEnvironmentTimeAvailableForRefreshsResultOutput{}, options).(GetFusionEnvironmentTimeAvailableForRefreshsResultOutput), nil
		}).(GetFusionEnvironmentTimeAvailableForRefreshsResultOutput)
}

// A collection of arguments for invoking getFusionEnvironmentTimeAvailableForRefreshs.
type GetFusionEnvironmentTimeAvailableForRefreshsOutputArgs struct {
	Filters GetFusionEnvironmentTimeAvailableForRefreshsFilterArrayInput `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringInput `pulumi:"fusionEnvironmentId"`
}

func (GetFusionEnvironmentTimeAvailableForRefreshsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentTimeAvailableForRefreshsArgs)(nil)).Elem()
}

// A collection of values returned by getFusionEnvironmentTimeAvailableForRefreshs.
type GetFusionEnvironmentTimeAvailableForRefreshsResultOutput struct{ *pulumi.OutputState }

func (GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentTimeAvailableForRefreshsResult)(nil)).Elem()
}

func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) ToGetFusionEnvironmentTimeAvailableForRefreshsResultOutput() GetFusionEnvironmentTimeAvailableForRefreshsResultOutput {
	return o
}

func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) ToGetFusionEnvironmentTimeAvailableForRefreshsResultOutputWithContext(ctx context.Context) GetFusionEnvironmentTimeAvailableForRefreshsResultOutput {
	return o
}

func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) Filters() GetFusionEnvironmentTimeAvailableForRefreshsFilterArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentTimeAvailableForRefreshsResult) []GetFusionEnvironmentTimeAvailableForRefreshsFilter {
		return v.Filters
	}).(GetFusionEnvironmentTimeAvailableForRefreshsFilterArrayOutput)
}

func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) FusionEnvironmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentTimeAvailableForRefreshsResult) string { return v.FusionEnvironmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentTimeAvailableForRefreshsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of time_available_for_refresh_collection.
func (o GetFusionEnvironmentTimeAvailableForRefreshsResultOutput) TimeAvailableForRefreshCollections() GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentTimeAvailableForRefreshsResult) []GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollection {
		return v.TimeAvailableForRefreshCollections
	}).(GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFusionEnvironmentTimeAvailableForRefreshsResultOutput{})
}
