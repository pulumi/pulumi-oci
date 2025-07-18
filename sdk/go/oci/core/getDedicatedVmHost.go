// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Dedicated Vm Host resource in Oracle Cloud Infrastructure Core service.
//
// Gets information about the specified dedicated virtual machine host.
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
//			_, err := core.GetDedicatedVmHost(ctx, &core.GetDedicatedVmHostArgs{
//				DedicatedVmHostId: testDedicatedVmHostOciCoreDedicatedVmHost.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDedicatedVmHost(ctx *pulumi.Context, args *LookupDedicatedVmHostArgs, opts ...pulumi.InvokeOption) (*LookupDedicatedVmHostResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDedicatedVmHostResult
	err := ctx.Invoke("oci:Core/getDedicatedVmHost:getDedicatedVmHost", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDedicatedVmHost.
type LookupDedicatedVmHostArgs struct {
	// The OCID of the dedicated VM host.
	DedicatedVmHostId string `pulumi:"dedicatedVmHostId"`
}

// A collection of values returned by getDedicatedVmHost.
type LookupDedicatedVmHostResult struct {
	// The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// A list of total and remaining CPU & memory per capacity bucket.
	CapacityBins []GetDedicatedVmHostCapacityBin `pulumi:"capacityBins"`
	// The OCID of the compartment that contains the dedicated virtual machine host.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the compute bare metal host.
	ComputeBareMetalHostId string `pulumi:"computeBareMetalHostId"`
	DedicatedVmHostId      string `pulumi:"dedicatedVmHostId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VMs.
	DedicatedVmHostShape string `pulumi:"dedicatedVmHostShape"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault).
	FaultDomain string `pulumi:"faultDomain"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated VM host.
	Id string `pulumi:"id"`
	// Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
	PlacementConstraintDetails []GetDedicatedVmHostPlacementConstraintDetail `pulumi:"placementConstraintDetails"`
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs float64 `pulumi:"remainingMemoryInGbs"`
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus float64 `pulumi:"remainingOcpus"`
	// The current state of the dedicated VM host.
	State string `pulumi:"state"`
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs float64 `pulumi:"totalMemoryInGbs"`
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus float64 `pulumi:"totalOcpus"`
}

func LookupDedicatedVmHostOutput(ctx *pulumi.Context, args LookupDedicatedVmHostOutputArgs, opts ...pulumi.InvokeOption) LookupDedicatedVmHostResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDedicatedVmHostResultOutput, error) {
			args := v.(LookupDedicatedVmHostArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getDedicatedVmHost:getDedicatedVmHost", args, LookupDedicatedVmHostResultOutput{}, options).(LookupDedicatedVmHostResultOutput), nil
		}).(LookupDedicatedVmHostResultOutput)
}

// A collection of arguments for invoking getDedicatedVmHost.
type LookupDedicatedVmHostOutputArgs struct {
	// The OCID of the dedicated VM host.
	DedicatedVmHostId pulumi.StringInput `pulumi:"dedicatedVmHostId"`
}

func (LookupDedicatedVmHostOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDedicatedVmHostArgs)(nil)).Elem()
}

// A collection of values returned by getDedicatedVmHost.
type LookupDedicatedVmHostResultOutput struct{ *pulumi.OutputState }

func (LookupDedicatedVmHostResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDedicatedVmHostResult)(nil)).Elem()
}

func (o LookupDedicatedVmHostResultOutput) ToLookupDedicatedVmHostResultOutput() LookupDedicatedVmHostResultOutput {
	return o
}

func (o LookupDedicatedVmHostResultOutput) ToLookupDedicatedVmHostResultOutputWithContext(ctx context.Context) LookupDedicatedVmHostResultOutput {
	return o
}

// The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
func (o LookupDedicatedVmHostResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// A list of total and remaining CPU & memory per capacity bucket.
func (o LookupDedicatedVmHostResultOutput) CapacityBins() GetDedicatedVmHostCapacityBinArrayOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) []GetDedicatedVmHostCapacityBin { return v.CapacityBins }).(GetDedicatedVmHostCapacityBinArrayOutput)
}

// The OCID of the compartment that contains the dedicated virtual machine host.
func (o LookupDedicatedVmHostResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the compute bare metal host.
func (o LookupDedicatedVmHostResultOutput) ComputeBareMetalHostId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.ComputeBareMetalHostId }).(pulumi.StringOutput)
}

func (o LookupDedicatedVmHostResultOutput) DedicatedVmHostId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.DedicatedVmHostId }).(pulumi.StringOutput)
}

// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VMs.
func (o LookupDedicatedVmHostResultOutput) DedicatedVmHostShape() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.DedicatedVmHostShape }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupDedicatedVmHostResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupDedicatedVmHostResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault).
func (o LookupDedicatedVmHostResultOutput) FaultDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.FaultDomain }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupDedicatedVmHostResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated VM host.
func (o LookupDedicatedVmHostResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.Id }).(pulumi.StringOutput)
}

// Generic placement details field which is overloaded with bare metal host id or host group id based on the resource we are targeting to launch.
func (o LookupDedicatedVmHostResultOutput) PlacementConstraintDetails() GetDedicatedVmHostPlacementConstraintDetailArrayOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) []GetDedicatedVmHostPlacementConstraintDetail {
		return v.PlacementConstraintDetails
	}).(GetDedicatedVmHostPlacementConstraintDetailArrayOutput)
}

// The current available memory of the dedicated VM host, in GBs.
func (o LookupDedicatedVmHostResultOutput) RemainingMemoryInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) float64 { return v.RemainingMemoryInGbs }).(pulumi.Float64Output)
}

// The current available OCPUs of the dedicated VM host.
func (o LookupDedicatedVmHostResultOutput) RemainingOcpus() pulumi.Float64Output {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) float64 { return v.RemainingOcpus }).(pulumi.Float64Output)
}

// The current state of the dedicated VM host.
func (o LookupDedicatedVmHostResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupDedicatedVmHostResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The current total memory of the dedicated VM host, in GBs.
func (o LookupDedicatedVmHostResultOutput) TotalMemoryInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) float64 { return v.TotalMemoryInGbs }).(pulumi.Float64Output)
}

// The current total OCPUs of the dedicated VM host.
func (o LookupDedicatedVmHostResultOutput) TotalOcpus() pulumi.Float64Output {
	return o.ApplyT(func(v LookupDedicatedVmHostResult) float64 { return v.TotalOcpus }).(pulumi.Float64Output)
}

func init() {
	pulumi.RegisterOutputType(LookupDedicatedVmHostResultOutput{})
}
