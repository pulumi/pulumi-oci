// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fusion Environment Data Masking Activities in Oracle Cloud Infrastructure Fusion Apps service.
//
// Returns a list of DataMaskingActivities.
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
//			_, err := functions.GetFusionEnvironmentDataMaskingActivities(ctx, &functions.GetFusionEnvironmentDataMaskingActivitiesArgs{
//				FusionEnvironmentId: testFusionEnvironment.Id,
//				State:               pulumi.StringRef(fusionEnvironmentDataMaskingActivityState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFusionEnvironmentDataMaskingActivities(ctx *pulumi.Context, args *GetFusionEnvironmentDataMaskingActivitiesArgs, opts ...pulumi.InvokeOption) (*GetFusionEnvironmentDataMaskingActivitiesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFusionEnvironmentDataMaskingActivitiesResult
	err := ctx.Invoke("oci:Functions/getFusionEnvironmentDataMaskingActivities:getFusionEnvironmentDataMaskingActivities", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFusionEnvironmentDataMaskingActivities.
type GetFusionEnvironmentDataMaskingActivitiesArgs struct {
	Filters []GetFusionEnvironmentDataMaskingActivitiesFilter `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
	// A filter that returns all resources that match the specified status
	State *string `pulumi:"state"`
}

// A collection of values returned by getFusionEnvironmentDataMaskingActivities.
type GetFusionEnvironmentDataMaskingActivitiesResult struct {
	// The list of data_masking_activity_collection.
	DataMaskingActivityCollections []GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollection `pulumi:"dataMaskingActivityCollections"`
	Filters                        []GetFusionEnvironmentDataMaskingActivitiesFilter                        `pulumi:"filters"`
	// Fusion Environment Identifier.
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the DataMaskingActivity.
	State *string `pulumi:"state"`
}

func GetFusionEnvironmentDataMaskingActivitiesOutput(ctx *pulumi.Context, args GetFusionEnvironmentDataMaskingActivitiesOutputArgs, opts ...pulumi.InvokeOption) GetFusionEnvironmentDataMaskingActivitiesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFusionEnvironmentDataMaskingActivitiesResultOutput, error) {
			args := v.(GetFusionEnvironmentDataMaskingActivitiesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Functions/getFusionEnvironmentDataMaskingActivities:getFusionEnvironmentDataMaskingActivities", args, GetFusionEnvironmentDataMaskingActivitiesResultOutput{}, options).(GetFusionEnvironmentDataMaskingActivitiesResultOutput), nil
		}).(GetFusionEnvironmentDataMaskingActivitiesResultOutput)
}

// A collection of arguments for invoking getFusionEnvironmentDataMaskingActivities.
type GetFusionEnvironmentDataMaskingActivitiesOutputArgs struct {
	Filters GetFusionEnvironmentDataMaskingActivitiesFilterArrayInput `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringInput `pulumi:"fusionEnvironmentId"`
	// A filter that returns all resources that match the specified status
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetFusionEnvironmentDataMaskingActivitiesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentDataMaskingActivitiesArgs)(nil)).Elem()
}

// A collection of values returned by getFusionEnvironmentDataMaskingActivities.
type GetFusionEnvironmentDataMaskingActivitiesResultOutput struct{ *pulumi.OutputState }

func (GetFusionEnvironmentDataMaskingActivitiesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentDataMaskingActivitiesResult)(nil)).Elem()
}

func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) ToGetFusionEnvironmentDataMaskingActivitiesResultOutput() GetFusionEnvironmentDataMaskingActivitiesResultOutput {
	return o
}

func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) ToGetFusionEnvironmentDataMaskingActivitiesResultOutputWithContext(ctx context.Context) GetFusionEnvironmentDataMaskingActivitiesResultOutput {
	return o
}

// The list of data_masking_activity_collection.
func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) DataMaskingActivityCollections() GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentDataMaskingActivitiesResult) []GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollection {
		return v.DataMaskingActivityCollections
	}).(GetFusionEnvironmentDataMaskingActivitiesDataMaskingActivityCollectionArrayOutput)
}

func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) Filters() GetFusionEnvironmentDataMaskingActivitiesFilterArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentDataMaskingActivitiesResult) []GetFusionEnvironmentDataMaskingActivitiesFilter {
		return v.Filters
	}).(GetFusionEnvironmentDataMaskingActivitiesFilterArrayOutput)
}

// Fusion Environment Identifier.
func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) FusionEnvironmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentDataMaskingActivitiesResult) string { return v.FusionEnvironmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentDataMaskingActivitiesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the DataMaskingActivity.
func (o GetFusionEnvironmentDataMaskingActivitiesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentDataMaskingActivitiesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFusionEnvironmentDataMaskingActivitiesResultOutput{})
}
