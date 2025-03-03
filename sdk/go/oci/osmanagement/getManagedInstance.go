// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Instance resource in Oracle Cloud Infrastructure OS Management service.
//
// Returns a specific Managed Instance.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/osmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagement.GetManagedInstance(ctx, &osmanagement.GetManagedInstanceArgs{
//				ManagedInstanceId: testManagedInstanceOciOsmanagementManagedInstance.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagedInstance(ctx *pulumi.Context, args *LookupManagedInstanceArgs, opts ...pulumi.InvokeOption) (*LookupManagedInstanceResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagedInstanceResult
	err := ctx.Invoke("oci:OsManagement/getManagedInstance:getManagedInstance", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedInstance.
type LookupManagedInstanceArgs struct {
	// OCID for the managed instance
	ManagedInstanceId string `pulumi:"managedInstanceId"`
}

// A collection of values returned by getManagedInstance.
type LookupManagedInstanceResult struct {
	// if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
	Autonomouses []GetManagedInstanceAutonomouse `pulumi:"autonomouses"`
	// Number of bug fix type updates available to be installed
	BugUpdatesAvailable int `pulumi:"bugUpdatesAvailable"`
	// list of child Software Sources attached to the Managed Instance
	ChildSoftwareSources []GetManagedInstanceChildSoftwareSource `pulumi:"childSoftwareSources"`
	// OCID for the Compartment
	CompartmentId string `pulumi:"compartmentId"`
	// Information specified by the user about the managed instance
	Description string `pulumi:"description"`
	// User friendly name
	DisplayName string `pulumi:"displayName"`
	// Number of enhancement type updates available to be installed
	EnhancementUpdatesAvailable int `pulumi:"enhancementUpdatesAvailable"`
	// software source identifier
	Id string `pulumi:"id"`
	// True if user allow data collection for this instance
	IsDataCollectionAuthorized bool `pulumi:"isDataCollectionAuthorized"`
	// Indicates whether a reboot is required to complete installation of updates.
	IsRebootRequired bool `pulumi:"isRebootRequired"`
	// The ksplice effective kernel version
	KspliceEffectiveKernelVersion string `pulumi:"kspliceEffectiveKernelVersion"`
	// Time at which the instance last booted
	LastBoot string `pulumi:"lastBoot"`
	// Time at which the instance last checked in
	LastCheckin string `pulumi:"lastCheckin"`
	// The ids of the managed instance groups of which this instance is a member.
	ManagedInstanceGroups []GetManagedInstanceManagedInstanceGroup `pulumi:"managedInstanceGroups"`
	ManagedInstanceId     string                                   `pulumi:"managedInstanceId"`
	// OCID of the ONS topic used to send notification to users
	NotificationTopicId string `pulumi:"notificationTopicId"`
	// The Operating System type of the managed instance.
	OsFamily string `pulumi:"osFamily"`
	// Operating System Kernel Version
	OsKernelVersion string `pulumi:"osKernelVersion"`
	// Operating System Name
	OsName string `pulumi:"osName"`
	// Operating System Version
	OsVersion string `pulumi:"osVersion"`
	// Number of non-classified updates available to be installed
	OtherUpdatesAvailable int `pulumi:"otherUpdatesAvailable"`
	// the parent (base) Software Source attached to the Managed Instance
	ParentSoftwareSources []GetManagedInstanceParentSoftwareSource `pulumi:"parentSoftwareSources"`
	// Number of scheduled jobs associated with this instance
	ScheduledJobCount int `pulumi:"scheduledJobCount"`
	// Number of security type updates available to be installed
	SecurityUpdatesAvailable int `pulumi:"securityUpdatesAvailable"`
	// status of the managed instance.
	Status string `pulumi:"status"`
	// Number of updates available to be installed
	UpdatesAvailable int `pulumi:"updatesAvailable"`
	// Number of work requests associated with this instance
	WorkRequestCount int `pulumi:"workRequestCount"`
}

func LookupManagedInstanceOutput(ctx *pulumi.Context, args LookupManagedInstanceOutputArgs, opts ...pulumi.InvokeOption) LookupManagedInstanceResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupManagedInstanceResultOutput, error) {
			args := v.(LookupManagedInstanceArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OsManagement/getManagedInstance:getManagedInstance", args, LookupManagedInstanceResultOutput{}, options).(LookupManagedInstanceResultOutput), nil
		}).(LookupManagedInstanceResultOutput)
}

// A collection of arguments for invoking getManagedInstance.
type LookupManagedInstanceOutputArgs struct {
	// OCID for the managed instance
	ManagedInstanceId pulumi.StringInput `pulumi:"managedInstanceId"`
}

func (LookupManagedInstanceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedInstanceArgs)(nil)).Elem()
}

// A collection of values returned by getManagedInstance.
type LookupManagedInstanceResultOutput struct{ *pulumi.OutputState }

func (LookupManagedInstanceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedInstanceResult)(nil)).Elem()
}

func (o LookupManagedInstanceResultOutput) ToLookupManagedInstanceResultOutput() LookupManagedInstanceResultOutput {
	return o
}

func (o LookupManagedInstanceResultOutput) ToLookupManagedInstanceResultOutputWithContext(ctx context.Context) LookupManagedInstanceResultOutput {
	return o
}

// if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
func (o LookupManagedInstanceResultOutput) Autonomouses() GetManagedInstanceAutonomouseArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) []GetManagedInstanceAutonomouse { return v.Autonomouses }).(GetManagedInstanceAutonomouseArrayOutput)
}

// Number of bug fix type updates available to be installed
func (o LookupManagedInstanceResultOutput) BugUpdatesAvailable() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.BugUpdatesAvailable }).(pulumi.IntOutput)
}

// list of child Software Sources attached to the Managed Instance
func (o LookupManagedInstanceResultOutput) ChildSoftwareSources() GetManagedInstanceChildSoftwareSourceArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) []GetManagedInstanceChildSoftwareSource {
		return v.ChildSoftwareSources
	}).(GetManagedInstanceChildSoftwareSourceArrayOutput)
}

// OCID for the Compartment
func (o LookupManagedInstanceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Information specified by the user about the managed instance
func (o LookupManagedInstanceResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.Description }).(pulumi.StringOutput)
}

// User friendly name
func (o LookupManagedInstanceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Number of enhancement type updates available to be installed
func (o LookupManagedInstanceResultOutput) EnhancementUpdatesAvailable() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.EnhancementUpdatesAvailable }).(pulumi.IntOutput)
}

// software source identifier
func (o LookupManagedInstanceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.Id }).(pulumi.StringOutput)
}

// True if user allow data collection for this instance
func (o LookupManagedInstanceResultOutput) IsDataCollectionAuthorized() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) bool { return v.IsDataCollectionAuthorized }).(pulumi.BoolOutput)
}

// Indicates whether a reboot is required to complete installation of updates.
func (o LookupManagedInstanceResultOutput) IsRebootRequired() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) bool { return v.IsRebootRequired }).(pulumi.BoolOutput)
}

// The ksplice effective kernel version
func (o LookupManagedInstanceResultOutput) KspliceEffectiveKernelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.KspliceEffectiveKernelVersion }).(pulumi.StringOutput)
}

// Time at which the instance last booted
func (o LookupManagedInstanceResultOutput) LastBoot() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.LastBoot }).(pulumi.StringOutput)
}

// Time at which the instance last checked in
func (o LookupManagedInstanceResultOutput) LastCheckin() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.LastCheckin }).(pulumi.StringOutput)
}

// The ids of the managed instance groups of which this instance is a member.
func (o LookupManagedInstanceResultOutput) ManagedInstanceGroups() GetManagedInstanceManagedInstanceGroupArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) []GetManagedInstanceManagedInstanceGroup {
		return v.ManagedInstanceGroups
	}).(GetManagedInstanceManagedInstanceGroupArrayOutput)
}

func (o LookupManagedInstanceResultOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

// OCID of the ONS topic used to send notification to users
func (o LookupManagedInstanceResultOutput) NotificationTopicId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.NotificationTopicId }).(pulumi.StringOutput)
}

// The Operating System type of the managed instance.
func (o LookupManagedInstanceResultOutput) OsFamily() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.OsFamily }).(pulumi.StringOutput)
}

// Operating System Kernel Version
func (o LookupManagedInstanceResultOutput) OsKernelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.OsKernelVersion }).(pulumi.StringOutput)
}

// Operating System Name
func (o LookupManagedInstanceResultOutput) OsName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.OsName }).(pulumi.StringOutput)
}

// Operating System Version
func (o LookupManagedInstanceResultOutput) OsVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.OsVersion }).(pulumi.StringOutput)
}

// Number of non-classified updates available to be installed
func (o LookupManagedInstanceResultOutput) OtherUpdatesAvailable() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.OtherUpdatesAvailable }).(pulumi.IntOutput)
}

// the parent (base) Software Source attached to the Managed Instance
func (o LookupManagedInstanceResultOutput) ParentSoftwareSources() GetManagedInstanceParentSoftwareSourceArrayOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) []GetManagedInstanceParentSoftwareSource {
		return v.ParentSoftwareSources
	}).(GetManagedInstanceParentSoftwareSourceArrayOutput)
}

// Number of scheduled jobs associated with this instance
func (o LookupManagedInstanceResultOutput) ScheduledJobCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.ScheduledJobCount }).(pulumi.IntOutput)
}

// Number of security type updates available to be installed
func (o LookupManagedInstanceResultOutput) SecurityUpdatesAvailable() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.SecurityUpdatesAvailable }).(pulumi.IntOutput)
}

// status of the managed instance.
func (o LookupManagedInstanceResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) string { return v.Status }).(pulumi.StringOutput)
}

// Number of updates available to be installed
func (o LookupManagedInstanceResultOutput) UpdatesAvailable() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.UpdatesAvailable }).(pulumi.IntOutput)
}

// Number of work requests associated with this instance
func (o LookupManagedInstanceResultOutput) WorkRequestCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagedInstanceResult) int { return v.WorkRequestCount }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagedInstanceResultOutput{})
}
