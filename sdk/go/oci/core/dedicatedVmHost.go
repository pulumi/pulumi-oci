// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Dedicated Vm Host resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new dedicated virtual machine host in the specified compartment and the specified availability domain.
// Dedicated virtual machine hosts enable you to run your Compute virtual machine (VM) instances on dedicated servers
// that are a single tenant and not shared with other customers.
// For more information, see [Dedicated Virtual Machine Hosts](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.NewDedicatedVmHost(ctx, "testDedicatedVmHost", &Core.DedicatedVmHostArgs{
//				AvailabilityDomain:   pulumi.Any(_var.Dedicated_vm_host_availability_domain),
//				CompartmentId:        pulumi.Any(_var.Compartment_id),
//				DedicatedVmHostShape: pulumi.Any(_var.Dedicated_vm_host_dedicated_vm_host_shape),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Dedicated_vm_host_display_name),
//				FaultDomain: pulumi.Any(_var.Dedicated_vm_host_fault_domain),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// DedicatedVmHosts can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Core/dedicatedVmHost:DedicatedVmHost test_dedicated_vm_host "id"
//
// ```
type DedicatedVmHost struct {
	pulumi.CustomResourceState

	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringOutput `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringOutput `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs pulumi.Float64Output `pulumi:"remainingMemoryInGbs"`
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus pulumi.Float64Output `pulumi:"remainingOcpus"`
	// The current state of the dedicated VM host.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs pulumi.Float64Output `pulumi:"totalMemoryInGbs"`
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus pulumi.Float64Output `pulumi:"totalOcpus"`
}

// NewDedicatedVmHost registers a new resource with the given unique name, arguments, and options.
func NewDedicatedVmHost(ctx *pulumi.Context,
	name string, args *DedicatedVmHostArgs, opts ...pulumi.ResourceOption) (*DedicatedVmHost, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AvailabilityDomain == nil {
		return nil, errors.New("invalid value for required argument 'AvailabilityDomain'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DedicatedVmHostShape == nil {
		return nil, errors.New("invalid value for required argument 'DedicatedVmHostShape'")
	}
	var resource DedicatedVmHost
	err := ctx.RegisterResource("oci:Core/dedicatedVmHost:DedicatedVmHost", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDedicatedVmHost gets an existing DedicatedVmHost resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDedicatedVmHost(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DedicatedVmHostState, opts ...pulumi.ResourceOption) (*DedicatedVmHost, error) {
	var resource DedicatedVmHost
	err := ctx.ReadResource("oci:Core/dedicatedVmHost:DedicatedVmHost", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DedicatedVmHost resources.
type dedicatedVmHostState struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape *string `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain *string `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs *float64 `pulumi:"remainingMemoryInGbs"`
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus *float64 `pulumi:"remainingOcpus"`
	// The current state of the dedicated VM host.
	State *string `pulumi:"state"`
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs *float64 `pulumi:"totalMemoryInGbs"`
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus *float64 `pulumi:"totalOcpus"`
}

type DedicatedVmHostState struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The current available memory of the dedicated VM host, in GBs.
	RemainingMemoryInGbs pulumi.Float64PtrInput
	// The current available OCPUs of the dedicated VM host.
	RemainingOcpus pulumi.Float64PtrInput
	// The current state of the dedicated VM host.
	State pulumi.StringPtrInput
	// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The current total memory of the dedicated VM host, in GBs.
	TotalMemoryInGbs pulumi.Float64PtrInput
	// The current total OCPUs of the dedicated VM host.
	TotalOcpus pulumi.Float64PtrInput
}

func (DedicatedVmHostState) ElementType() reflect.Type {
	return reflect.TypeOf((*dedicatedVmHostState)(nil)).Elem()
}

type dedicatedVmHostArgs struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// (Updatable) The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape string `pulumi:"dedicatedVmHostShape"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain *string `pulumi:"faultDomain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a DedicatedVmHost resource.
type DedicatedVmHostArgs struct {
	// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput
	// (Updatable) The OCID of the compartment.
	CompartmentId pulumi.StringInput
	// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
	DedicatedVmHostShape pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
	FaultDomain pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
}

func (DedicatedVmHostArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dedicatedVmHostArgs)(nil)).Elem()
}

type DedicatedVmHostInput interface {
	pulumi.Input

	ToDedicatedVmHostOutput() DedicatedVmHostOutput
	ToDedicatedVmHostOutputWithContext(ctx context.Context) DedicatedVmHostOutput
}

func (*DedicatedVmHost) ElementType() reflect.Type {
	return reflect.TypeOf((**DedicatedVmHost)(nil)).Elem()
}

func (i *DedicatedVmHost) ToDedicatedVmHostOutput() DedicatedVmHostOutput {
	return i.ToDedicatedVmHostOutputWithContext(context.Background())
}

func (i *DedicatedVmHost) ToDedicatedVmHostOutputWithContext(ctx context.Context) DedicatedVmHostOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DedicatedVmHostOutput)
}

// DedicatedVmHostArrayInput is an input type that accepts DedicatedVmHostArray and DedicatedVmHostArrayOutput values.
// You can construct a concrete instance of `DedicatedVmHostArrayInput` via:
//
//	DedicatedVmHostArray{ DedicatedVmHostArgs{...} }
type DedicatedVmHostArrayInput interface {
	pulumi.Input

	ToDedicatedVmHostArrayOutput() DedicatedVmHostArrayOutput
	ToDedicatedVmHostArrayOutputWithContext(context.Context) DedicatedVmHostArrayOutput
}

type DedicatedVmHostArray []DedicatedVmHostInput

func (DedicatedVmHostArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DedicatedVmHost)(nil)).Elem()
}

func (i DedicatedVmHostArray) ToDedicatedVmHostArrayOutput() DedicatedVmHostArrayOutput {
	return i.ToDedicatedVmHostArrayOutputWithContext(context.Background())
}

func (i DedicatedVmHostArray) ToDedicatedVmHostArrayOutputWithContext(ctx context.Context) DedicatedVmHostArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DedicatedVmHostArrayOutput)
}

// DedicatedVmHostMapInput is an input type that accepts DedicatedVmHostMap and DedicatedVmHostMapOutput values.
// You can construct a concrete instance of `DedicatedVmHostMapInput` via:
//
//	DedicatedVmHostMap{ "key": DedicatedVmHostArgs{...} }
type DedicatedVmHostMapInput interface {
	pulumi.Input

	ToDedicatedVmHostMapOutput() DedicatedVmHostMapOutput
	ToDedicatedVmHostMapOutputWithContext(context.Context) DedicatedVmHostMapOutput
}

type DedicatedVmHostMap map[string]DedicatedVmHostInput

func (DedicatedVmHostMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DedicatedVmHost)(nil)).Elem()
}

func (i DedicatedVmHostMap) ToDedicatedVmHostMapOutput() DedicatedVmHostMapOutput {
	return i.ToDedicatedVmHostMapOutputWithContext(context.Background())
}

func (i DedicatedVmHostMap) ToDedicatedVmHostMapOutputWithContext(ctx context.Context) DedicatedVmHostMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DedicatedVmHostMapOutput)
}

type DedicatedVmHostOutput struct{ *pulumi.OutputState }

func (DedicatedVmHostOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DedicatedVmHost)(nil)).Elem()
}

func (o DedicatedVmHostOutput) ToDedicatedVmHostOutput() DedicatedVmHostOutput {
	return o
}

func (o DedicatedVmHostOutput) ToDedicatedVmHostOutputWithContext(ctx context.Context) DedicatedVmHostOutput {
	return o
}

// The availability domain of the dedicated virtual machine host.  Example: `Uocm:PHX-AD-1`
func (o DedicatedVmHostOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment.
func (o DedicatedVmHostOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VM instances launched on the dedicated virtual machine host.
func (o DedicatedVmHostOutput) DedicatedVmHostShape() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.DedicatedVmHostShape }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o DedicatedVmHostOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o DedicatedVmHostOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The fault domain for the dedicated virtual machine host's assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the system selects one for you. To change the fault domain for a dedicated virtual machine host, delete it and create a new dedicated virtual machine host in the preferred fault domain.
func (o DedicatedVmHostOutput) FaultDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.FaultDomain }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o DedicatedVmHostOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The current available memory of the dedicated VM host, in GBs.
func (o DedicatedVmHostOutput) RemainingMemoryInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.Float64Output { return v.RemainingMemoryInGbs }).(pulumi.Float64Output)
}

// The current available OCPUs of the dedicated VM host.
func (o DedicatedVmHostOutput) RemainingOcpus() pulumi.Float64Output {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.Float64Output { return v.RemainingOcpus }).(pulumi.Float64Output)
}

// The current state of the dedicated VM host.
func (o DedicatedVmHostOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o DedicatedVmHostOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The current total memory of the dedicated VM host, in GBs.
func (o DedicatedVmHostOutput) TotalMemoryInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.Float64Output { return v.TotalMemoryInGbs }).(pulumi.Float64Output)
}

// The current total OCPUs of the dedicated VM host.
func (o DedicatedVmHostOutput) TotalOcpus() pulumi.Float64Output {
	return o.ApplyT(func(v *DedicatedVmHost) pulumi.Float64Output { return v.TotalOcpus }).(pulumi.Float64Output)
}

type DedicatedVmHostArrayOutput struct{ *pulumi.OutputState }

func (DedicatedVmHostArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DedicatedVmHost)(nil)).Elem()
}

func (o DedicatedVmHostArrayOutput) ToDedicatedVmHostArrayOutput() DedicatedVmHostArrayOutput {
	return o
}

func (o DedicatedVmHostArrayOutput) ToDedicatedVmHostArrayOutputWithContext(ctx context.Context) DedicatedVmHostArrayOutput {
	return o
}

func (o DedicatedVmHostArrayOutput) Index(i pulumi.IntInput) DedicatedVmHostOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DedicatedVmHost {
		return vs[0].([]*DedicatedVmHost)[vs[1].(int)]
	}).(DedicatedVmHostOutput)
}

type DedicatedVmHostMapOutput struct{ *pulumi.OutputState }

func (DedicatedVmHostMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DedicatedVmHost)(nil)).Elem()
}

func (o DedicatedVmHostMapOutput) ToDedicatedVmHostMapOutput() DedicatedVmHostMapOutput {
	return o
}

func (o DedicatedVmHostMapOutput) ToDedicatedVmHostMapOutputWithContext(ctx context.Context) DedicatedVmHostMapOutput {
	return o
}

func (o DedicatedVmHostMapOutput) MapIndex(k pulumi.StringInput) DedicatedVmHostOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DedicatedVmHost {
		return vs[0].(map[string]*DedicatedVmHost)[vs[1].(string)]
	}).(DedicatedVmHostOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DedicatedVmHostInput)(nil)).Elem(), &DedicatedVmHost{})
	pulumi.RegisterInputType(reflect.TypeOf((*DedicatedVmHostArrayInput)(nil)).Elem(), DedicatedVmHostArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DedicatedVmHostMapInput)(nil)).Elem(), DedicatedVmHostMap{})
	pulumi.RegisterOutputType(DedicatedVmHostOutput{})
	pulumi.RegisterOutputType(DedicatedVmHostArrayOutput{})
	pulumi.RegisterOutputType(DedicatedVmHostMapOutput{})
}