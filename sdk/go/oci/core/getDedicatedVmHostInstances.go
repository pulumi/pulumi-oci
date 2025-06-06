// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Dedicated Vm Hosts Instances in Oracle Cloud Infrastructure Core service.
//
// Returns the list of instances on the dedicated virtual machine hosts that match the specified criteria.
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
//			_, err := core.GetDedicatedVmHostInstances(ctx, &core.GetDedicatedVmHostInstancesArgs{
//				CompartmentId:      compartmentId,
//				DedicatedVmHostId:  testDedicatedVmHost.Id,
//				AvailabilityDomain: pulumi.StringRef(dedicatedVmHostsInstanceAvailabilityDomain),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDedicatedVmHostInstances(ctx *pulumi.Context, args *GetDedicatedVmHostInstancesArgs, opts ...pulumi.InvokeOption) (*GetDedicatedVmHostInstancesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDedicatedVmHostInstancesResult
	err := ctx.Invoke("oci:Core/getDedicatedVmHostInstances:getDedicatedVmHostInstances", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDedicatedVmHostInstances.
type GetDedicatedVmHostInstancesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the dedicated VM host.
	DedicatedVmHostId string                              `pulumi:"dedicatedVmHostId"`
	Filters           []GetDedicatedVmHostInstancesFilter `pulumi:"filters"`
}

// A collection of values returned by getDedicatedVmHostInstances.
type GetDedicatedVmHostInstancesResult struct {
	// The availability domain the virtual machine instance is running in.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment that contains the virtual machine instance.
	CompartmentId     string `pulumi:"compartmentId"`
	DedicatedVmHostId string `pulumi:"dedicatedVmHostId"`
	// The list of dedicated_vm_host_instances.
	DedicatedVmHostInstances []GetDedicatedVmHostInstancesDedicatedVmHostInstance `pulumi:"dedicatedVmHostInstances"`
	Filters                  []GetDedicatedVmHostInstancesFilter                  `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetDedicatedVmHostInstancesOutput(ctx *pulumi.Context, args GetDedicatedVmHostInstancesOutputArgs, opts ...pulumi.InvokeOption) GetDedicatedVmHostInstancesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDedicatedVmHostInstancesResultOutput, error) {
			args := v.(GetDedicatedVmHostInstancesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getDedicatedVmHostInstances:getDedicatedVmHostInstances", args, GetDedicatedVmHostInstancesResultOutput{}, options).(GetDedicatedVmHostInstancesResultOutput), nil
		}).(GetDedicatedVmHostInstancesResultOutput)
}

// A collection of arguments for invoking getDedicatedVmHostInstances.
type GetDedicatedVmHostInstancesOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The OCID of the dedicated VM host.
	DedicatedVmHostId pulumi.StringInput                          `pulumi:"dedicatedVmHostId"`
	Filters           GetDedicatedVmHostInstancesFilterArrayInput `pulumi:"filters"`
}

func (GetDedicatedVmHostInstancesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDedicatedVmHostInstancesArgs)(nil)).Elem()
}

// A collection of values returned by getDedicatedVmHostInstances.
type GetDedicatedVmHostInstancesResultOutput struct{ *pulumi.OutputState }

func (GetDedicatedVmHostInstancesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDedicatedVmHostInstancesResult)(nil)).Elem()
}

func (o GetDedicatedVmHostInstancesResultOutput) ToGetDedicatedVmHostInstancesResultOutput() GetDedicatedVmHostInstancesResultOutput {
	return o
}

func (o GetDedicatedVmHostInstancesResultOutput) ToGetDedicatedVmHostInstancesResultOutputWithContext(ctx context.Context) GetDedicatedVmHostInstancesResultOutput {
	return o
}

// The availability domain the virtual machine instance is running in.  Example: `Uocm:PHX-AD-1`
func (o GetDedicatedVmHostInstancesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment that contains the virtual machine instance.
func (o GetDedicatedVmHostInstancesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetDedicatedVmHostInstancesResultOutput) DedicatedVmHostId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) string { return v.DedicatedVmHostId }).(pulumi.StringOutput)
}

// The list of dedicated_vm_host_instances.
func (o GetDedicatedVmHostInstancesResultOutput) DedicatedVmHostInstances() GetDedicatedVmHostInstancesDedicatedVmHostInstanceArrayOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) []GetDedicatedVmHostInstancesDedicatedVmHostInstance {
		return v.DedicatedVmHostInstances
	}).(GetDedicatedVmHostInstancesDedicatedVmHostInstanceArrayOutput)
}

func (o GetDedicatedVmHostInstancesResultOutput) Filters() GetDedicatedVmHostInstancesFilterArrayOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) []GetDedicatedVmHostInstancesFilter { return v.Filters }).(GetDedicatedVmHostInstancesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDedicatedVmHostInstancesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDedicatedVmHostInstancesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDedicatedVmHostInstancesResultOutput{})
}
