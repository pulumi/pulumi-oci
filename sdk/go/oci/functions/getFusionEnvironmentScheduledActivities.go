// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fusion Environment Scheduled Activities in Oracle Cloud Infrastructure Fusion Apps service.
//
// Returns a list of ScheduledActivities.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Functions"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Functions.GetFusionEnvironmentScheduledActivities(ctx, &functions.GetFusionEnvironmentScheduledActivitiesArgs{
//				FusionEnvironmentId:                    oci_fusion_apps_fusion_environment.Test_fusion_environment.Id,
//				DisplayName:                            pulumi.StringRef(_var.Fusion_environment_scheduled_activity_display_name),
//				RunCycle:                               pulumi.StringRef(_var.Fusion_environment_scheduled_activity_run_cycle),
//				State:                                  pulumi.StringRef(_var.Fusion_environment_scheduled_activity_state),
//				TimeExpectedFinishLessThanOrEqualTo:    pulumi.StringRef(_var.Fusion_environment_scheduled_activity_time_expected_finish_less_than_or_equal_to),
//				TimeScheduledStartGreaterThanOrEqualTo: pulumi.StringRef(_var.Fusion_environment_scheduled_activity_time_scheduled_start_greater_than_or_equal_to),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFusionEnvironmentScheduledActivities(ctx *pulumi.Context, args *GetFusionEnvironmentScheduledActivitiesArgs, opts ...pulumi.InvokeOption) (*GetFusionEnvironmentScheduledActivitiesResult, error) {
	var rv GetFusionEnvironmentScheduledActivitiesResult
	err := ctx.Invoke("oci:Functions/getFusionEnvironmentScheduledActivities:getFusionEnvironmentScheduledActivities", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFusionEnvironmentScheduledActivities.
type GetFusionEnvironmentScheduledActivitiesArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                                         `pulumi:"displayName"`
	Filters     []GetFusionEnvironmentScheduledActivitiesFilter `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
	// A filter that returns all resources that match the specified run cycle.
	RunCycle *string `pulumi:"runCycle"`
	// A filter that returns all resources that match the specified status
	State *string `pulumi:"state"`
	// A filter that returns all resources that end before this date
	TimeExpectedFinishLessThanOrEqualTo *string `pulumi:"timeExpectedFinishLessThanOrEqualTo"`
	// A filter that returns all resources that are scheduled after this date
	TimeScheduledStartGreaterThanOrEqualTo *string `pulumi:"timeScheduledStartGreaterThanOrEqualTo"`
}

// A collection of values returned by getFusionEnvironmentScheduledActivities.
type GetFusionEnvironmentScheduledActivitiesResult struct {
	// scheduled activity display name, can be renamed.
	DisplayName *string                                         `pulumi:"displayName"`
	Filters     []GetFusionEnvironmentScheduledActivitiesFilter `pulumi:"filters"`
	// FAaaS Environment Identifier.
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// run cadence.
	RunCycle *string `pulumi:"runCycle"`
	// The list of scheduled_activity_collection.
	ScheduledActivityCollections []GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection `pulumi:"scheduledActivityCollections"`
	// The current state of the scheduledActivity.
	State                                  *string `pulumi:"state"`
	TimeExpectedFinishLessThanOrEqualTo    *string `pulumi:"timeExpectedFinishLessThanOrEqualTo"`
	TimeScheduledStartGreaterThanOrEqualTo *string `pulumi:"timeScheduledStartGreaterThanOrEqualTo"`
}

func GetFusionEnvironmentScheduledActivitiesOutput(ctx *pulumi.Context, args GetFusionEnvironmentScheduledActivitiesOutputArgs, opts ...pulumi.InvokeOption) GetFusionEnvironmentScheduledActivitiesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFusionEnvironmentScheduledActivitiesResult, error) {
			args := v.(GetFusionEnvironmentScheduledActivitiesArgs)
			r, err := GetFusionEnvironmentScheduledActivities(ctx, &args, opts...)
			var s GetFusionEnvironmentScheduledActivitiesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFusionEnvironmentScheduledActivitiesResultOutput)
}

// A collection of arguments for invoking getFusionEnvironmentScheduledActivities.
type GetFusionEnvironmentScheduledActivitiesOutputArgs struct {
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                                   `pulumi:"displayName"`
	Filters     GetFusionEnvironmentScheduledActivitiesFilterArrayInput `pulumi:"filters"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringInput `pulumi:"fusionEnvironmentId"`
	// A filter that returns all resources that match the specified run cycle.
	RunCycle pulumi.StringPtrInput `pulumi:"runCycle"`
	// A filter that returns all resources that match the specified status
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter that returns all resources that end before this date
	TimeExpectedFinishLessThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeExpectedFinishLessThanOrEqualTo"`
	// A filter that returns all resources that are scheduled after this date
	TimeScheduledStartGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeScheduledStartGreaterThanOrEqualTo"`
}

func (GetFusionEnvironmentScheduledActivitiesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentScheduledActivitiesArgs)(nil)).Elem()
}

// A collection of values returned by getFusionEnvironmentScheduledActivities.
type GetFusionEnvironmentScheduledActivitiesResultOutput struct{ *pulumi.OutputState }

func (GetFusionEnvironmentScheduledActivitiesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentScheduledActivitiesResult)(nil)).Elem()
}

func (o GetFusionEnvironmentScheduledActivitiesResultOutput) ToGetFusionEnvironmentScheduledActivitiesResultOutput() GetFusionEnvironmentScheduledActivitiesResultOutput {
	return o
}

func (o GetFusionEnvironmentScheduledActivitiesResultOutput) ToGetFusionEnvironmentScheduledActivitiesResultOutputWithContext(ctx context.Context) GetFusionEnvironmentScheduledActivitiesResultOutput {
	return o
}

// scheduled activity display name, can be renamed.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetFusionEnvironmentScheduledActivitiesResultOutput) Filters() GetFusionEnvironmentScheduledActivitiesFilterArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) []GetFusionEnvironmentScheduledActivitiesFilter {
		return v.Filters
	}).(GetFusionEnvironmentScheduledActivitiesFilterArrayOutput)
}

// FAaaS Environment Identifier.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) FusionEnvironmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) string { return v.FusionEnvironmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) string { return v.Id }).(pulumi.StringOutput)
}

// run cadence.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) RunCycle() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) *string { return v.RunCycle }).(pulumi.StringPtrOutput)
}

// The list of scheduled_activity_collection.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) ScheduledActivityCollections() GetFusionEnvironmentScheduledActivitiesScheduledActivityCollectionArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) []GetFusionEnvironmentScheduledActivitiesScheduledActivityCollection {
		return v.ScheduledActivityCollections
	}).(GetFusionEnvironmentScheduledActivitiesScheduledActivityCollectionArrayOutput)
}

// The current state of the scheduledActivity.
func (o GetFusionEnvironmentScheduledActivitiesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetFusionEnvironmentScheduledActivitiesResultOutput) TimeExpectedFinishLessThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) *string {
		return v.TimeExpectedFinishLessThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func (o GetFusionEnvironmentScheduledActivitiesResultOutput) TimeScheduledStartGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFusionEnvironmentScheduledActivitiesResult) *string {
		return v.TimeScheduledStartGreaterThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFusionEnvironmentScheduledActivitiesResultOutput{})
}