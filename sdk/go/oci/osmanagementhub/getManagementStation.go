// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Management Station resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Gets information about the specified management station.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OsManagementHub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OsManagementHub.GetManagementStation(ctx, &osmanagementhub.GetManagementStationArgs{
//				ManagementStationId: oci_os_management_hub_management_station.Test_management_station.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagementStation(ctx *pulumi.Context, args *LookupManagementStationArgs, opts ...pulumi.InvokeOption) (*LookupManagementStationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagementStationResult
	err := ctx.Invoke("oci:OsManagementHub/getManagementStation:getManagementStation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementStation.
type LookupManagementStationArgs struct {
	// The OCID of the management station.
	ManagementStationId string `pulumi:"managementStationId"`
}

// A collection of values returned by getManagementStation.
type LookupManagementStationResult struct {
	// The OCID of the tenancy containing the Management Station.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Details describing the ManagementStation config.
	Description string `pulumi:"description"`
	// ManagementStation name
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Name of the host
	Hostname string `pulumi:"hostname"`
	// OCID for the ManagementStation config
	Id string `pulumi:"id"`
	// OCID for the Instance associated with the Management Station.
	ManagedInstanceId   string `pulumi:"managedInstanceId"`
	ManagementStationId string `pulumi:"managementStationId"`
	// A decimal number representing the mirror capacity
	MirrorCapacity int `pulumi:"mirrorCapacity"`
	// Status summary of all repos
	MirrorSyncStatuses []GetManagementStationMirrorSyncStatus `pulumi:"mirrorSyncStatuses"`
	// Information for a mirror configuration
	Mirrors []GetManagementStationMirror `pulumi:"mirrors"`
	// A decimal number representing the completeness percentage
	OverallPercentage int `pulumi:"overallPercentage"`
	// Current state of the mirroring
	OverallState string `pulumi:"overallState"`
	// OCID of the Profile associated with the Station
	ProfileId string `pulumi:"profileId"`
	// Information for a proxy configuration
	Proxies []GetManagementStationProxy `pulumi:"proxies"`
	// OCID of the Scheduled Job for mirror sync
	ScheduledJobId string `pulumi:"scheduledJobId"`
	// The current state of the Management Station config.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// A decimal number representing the total of repos
	TotalMirrors int `pulumi:"totalMirrors"`
}

func LookupManagementStationOutput(ctx *pulumi.Context, args LookupManagementStationOutputArgs, opts ...pulumi.InvokeOption) LookupManagementStationResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupManagementStationResult, error) {
			args := v.(LookupManagementStationArgs)
			r, err := LookupManagementStation(ctx, &args, opts...)
			var s LookupManagementStationResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupManagementStationResultOutput)
}

// A collection of arguments for invoking getManagementStation.
type LookupManagementStationOutputArgs struct {
	// The OCID of the management station.
	ManagementStationId pulumi.StringInput `pulumi:"managementStationId"`
}

func (LookupManagementStationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementStationArgs)(nil)).Elem()
}

// A collection of values returned by getManagementStation.
type LookupManagementStationResultOutput struct{ *pulumi.OutputState }

func (LookupManagementStationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementStationResult)(nil)).Elem()
}

func (o LookupManagementStationResultOutput) ToLookupManagementStationResultOutput() LookupManagementStationResultOutput {
	return o
}

func (o LookupManagementStationResultOutput) ToLookupManagementStationResultOutputWithContext(ctx context.Context) LookupManagementStationResultOutput {
	return o
}

func (o LookupManagementStationResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupManagementStationResult] {
	return pulumix.Output[LookupManagementStationResult]{
		OutputState: o.OutputState,
	}
}

// The OCID of the tenancy containing the Management Station.
func (o LookupManagementStationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupManagementStationResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Details describing the ManagementStation config.
func (o LookupManagementStationResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Description }).(pulumi.StringOutput)
}

// ManagementStation name
func (o LookupManagementStationResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupManagementStationResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Name of the host
func (o LookupManagementStationResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// OCID for the ManagementStation config
func (o LookupManagementStationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Id }).(pulumi.StringOutput)
}

// OCID for the Instance associated with the Management Station.
func (o LookupManagementStationResultOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

func (o LookupManagementStationResultOutput) ManagementStationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ManagementStationId }).(pulumi.StringOutput)
}

// A decimal number representing the mirror capacity
func (o LookupManagementStationResultOutput) MirrorCapacity() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.MirrorCapacity }).(pulumi.IntOutput)
}

// Status summary of all repos
func (o LookupManagementStationResultOutput) MirrorSyncStatuses() GetManagementStationMirrorSyncStatusArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationMirrorSyncStatus {
		return v.MirrorSyncStatuses
	}).(GetManagementStationMirrorSyncStatusArrayOutput)
}

// Information for a mirror configuration
func (o LookupManagementStationResultOutput) Mirrors() GetManagementStationMirrorArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationMirror { return v.Mirrors }).(GetManagementStationMirrorArrayOutput)
}

// A decimal number representing the completeness percentage
func (o LookupManagementStationResultOutput) OverallPercentage() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.OverallPercentage }).(pulumi.IntOutput)
}

// Current state of the mirroring
func (o LookupManagementStationResultOutput) OverallState() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.OverallState }).(pulumi.StringOutput)
}

// OCID of the Profile associated with the Station
func (o LookupManagementStationResultOutput) ProfileId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ProfileId }).(pulumi.StringOutput)
}

// Information for a proxy configuration
func (o LookupManagementStationResultOutput) Proxies() GetManagementStationProxyArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationProxy { return v.Proxies }).(GetManagementStationProxyArrayOutput)
}

// OCID of the Scheduled Job for mirror sync
func (o LookupManagementStationResultOutput) ScheduledJobId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ScheduledJobId }).(pulumi.StringOutput)
}

// The current state of the Management Station config.
func (o LookupManagementStationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupManagementStationResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// A decimal number representing the total of repos
func (o LookupManagementStationResultOutput) TotalMirrors() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.TotalMirrors }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagementStationResultOutput{})
}