// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package resourcescheduler

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Schedules in Oracle Cloud Infrastructure Resource Scheduler service.
//
// This API gets a list of schedules. You must provide either a compartmentId or a scheduleId or both. You can list resources in this compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This is required unless a specific schedule ID is passed.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/resourcescheduler"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := resourcescheduler.GetSchedules(ctx, &resourcescheduler.GetSchedulesArgs{
//				CompartmentId: pulumi.StringRef(compartmentId),
//				DisplayName:   pulumi.StringRef(scheduleDisplayName),
//				ResourceId:    pulumi.StringRef(testResource.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSchedules(ctx *pulumi.Context, args *GetSchedulesArgs, opts ...pulumi.InvokeOption) (*GetSchedulesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSchedulesResult
	err := ctx.Invoke("oci:ResourceScheduler/getSchedules:getSchedules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSchedules.
type GetSchedulesArgs struct {
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources. You need to at least provide either `compartmentId` or `scheduleId` or both.
	CompartmentId *string `pulumi:"compartmentId"`
	// This is a filter to return only resources that match the given display name exactly.
	DisplayName *string              `pulumi:"displayName"`
	Filters     []GetSchedulesFilter `pulumi:"filters"`
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource affected by the work request.
	ResourceId *string `pulumi:"resourceId"`
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.  You need to at least provide either `compartmentId` or `scheduleId` or both.
	ScheduleId *string `pulumi:"scheduleId"`
	// This is a filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getSchedules.
type GetSchedulesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the schedule is created
	CompartmentId *string `pulumi:"compartmentId"`
	// This is a user-friendly name for the schedule. It does not have to be unique, and it's changeable.
	DisplayName *string              `pulumi:"displayName"`
	Filters     []GetSchedulesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id         string  `pulumi:"id"`
	ResourceId *string `pulumi:"resourceId"`
	// The list of schedule_collection.
	ScheduleCollections []GetSchedulesScheduleCollection `pulumi:"scheduleCollections"`
	ScheduleId          *string                          `pulumi:"scheduleId"`
	// This is the current state of a schedule.
	State *string `pulumi:"state"`
}

func GetSchedulesOutput(ctx *pulumi.Context, args GetSchedulesOutputArgs, opts ...pulumi.InvokeOption) GetSchedulesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSchedulesResultOutput, error) {
			args := v.(GetSchedulesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ResourceScheduler/getSchedules:getSchedules", args, GetSchedulesResultOutput{}, options).(GetSchedulesResultOutput), nil
		}).(GetSchedulesResultOutput)
}

// A collection of arguments for invoking getSchedules.
type GetSchedulesOutputArgs struct {
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources. You need to at least provide either `compartmentId` or `scheduleId` or both.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// This is a filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput        `pulumi:"displayName"`
	Filters     GetSchedulesFilterArrayInput `pulumi:"filters"`
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource affected by the work request.
	ResourceId pulumi.StringPtrInput `pulumi:"resourceId"`
	// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.  You need to at least provide either `compartmentId` or `scheduleId` or both.
	ScheduleId pulumi.StringPtrInput `pulumi:"scheduleId"`
	// This is a filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetSchedulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSchedulesArgs)(nil)).Elem()
}

// A collection of values returned by getSchedules.
type GetSchedulesResultOutput struct{ *pulumi.OutputState }

func (GetSchedulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSchedulesResult)(nil)).Elem()
}

func (o GetSchedulesResultOutput) ToGetSchedulesResultOutput() GetSchedulesResultOutput {
	return o
}

func (o GetSchedulesResultOutput) ToGetSchedulesResultOutputWithContext(ctx context.Context) GetSchedulesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the schedule is created
func (o GetSchedulesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSchedulesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// This is a user-friendly name for the schedule. It does not have to be unique, and it's changeable.
func (o GetSchedulesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSchedulesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetSchedulesResultOutput) Filters() GetSchedulesFilterArrayOutput {
	return o.ApplyT(func(v GetSchedulesResult) []GetSchedulesFilter { return v.Filters }).(GetSchedulesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSchedulesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSchedulesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetSchedulesResultOutput) ResourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSchedulesResult) *string { return v.ResourceId }).(pulumi.StringPtrOutput)
}

// The list of schedule_collection.
func (o GetSchedulesResultOutput) ScheduleCollections() GetSchedulesScheduleCollectionArrayOutput {
	return o.ApplyT(func(v GetSchedulesResult) []GetSchedulesScheduleCollection { return v.ScheduleCollections }).(GetSchedulesScheduleCollectionArrayOutput)
}

func (o GetSchedulesResultOutput) ScheduleId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSchedulesResult) *string { return v.ScheduleId }).(pulumi.StringPtrOutput)
}

// This is the current state of a schedule.
func (o GetSchedulesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSchedulesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSchedulesResultOutput{})
}
