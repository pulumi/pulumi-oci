// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Console History resource in Oracle Cloud Infrastructure Core service.
//
// Captures the most recent serial console data (up to a megabyte) for the
// specified instance.
//
// The `CaptureConsoleHistory` operation works with the other console history operations
// as described below.
//
//  1. Use `CaptureConsoleHistory` to request the capture of up to a megabyte of the
//     most recent console history. This call returns a `ConsoleHistory`
//     object. The object will have a state of REQUESTED.
//  2. Wait for the capture operation to succeed by polling `GetConsoleHistory` with
//     the identifier of the console history metadata. The state of the
//     `ConsoleHistory` object will go from REQUESTED to GETTING-HISTORY and
//     then SUCCEEDED (or FAILED).
//  3. Use `GetConsoleHistoryContent` to get the actual console history data (not the
//     metadata).
//  4. Optionally, use `DeleteConsoleHistory` to delete the console history metadata
//     and the console history data.
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
//			_, err := Core.NewConsoleHistory(ctx, "testConsoleHistory", &Core.ConsoleHistoryArgs{
//				InstanceId: pulumi.Any(oci_core_instance.Test_instance.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Console_history_display_name),
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
// ConsoleHistories can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Core/consoleHistory:ConsoleHistory test_console_history "id"
//
// ```
type ConsoleHistory struct {
	pulumi.CustomResourceState

	// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The OCID of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the instance to get the console history from.
	InstanceId pulumi.StringOutput `pulumi:"instanceId"`
	// The current state of the console history.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the history was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewConsoleHistory registers a new resource with the given unique name, arguments, and options.
func NewConsoleHistory(ctx *pulumi.Context,
	name string, args *ConsoleHistoryArgs, opts ...pulumi.ResourceOption) (*ConsoleHistory, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.InstanceId == nil {
		return nil, errors.New("invalid value for required argument 'InstanceId'")
	}
	var resource ConsoleHistory
	err := ctx.RegisterResource("oci:Core/consoleHistory:ConsoleHistory", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetConsoleHistory gets an existing ConsoleHistory resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetConsoleHistory(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ConsoleHistoryState, opts ...pulumi.ResourceOption) (*ConsoleHistory, error) {
	var resource ConsoleHistory
	err := ctx.ReadResource("oci:Core/consoleHistory:ConsoleHistory", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ConsoleHistory resources.
type consoleHistoryState struct {
	// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the instance to get the console history from.
	InstanceId *string `pulumi:"instanceId"`
	// The current state of the console history.
	State *string `pulumi:"state"`
	// The date and time the history was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type ConsoleHistoryState struct {
	// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// The OCID of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the instance to get the console history from.
	InstanceId pulumi.StringPtrInput
	// The current state of the console history.
	State pulumi.StringPtrInput
	// The date and time the history was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (ConsoleHistoryState) ElementType() reflect.Type {
	return reflect.TypeOf((*consoleHistoryState)(nil)).Elem()
}

type consoleHistoryArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the instance to get the console history from.
	InstanceId string `pulumi:"instanceId"`
}

// The set of arguments for constructing a ConsoleHistory resource.
type ConsoleHistoryArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the instance to get the console history from.
	InstanceId pulumi.StringInput
}

func (ConsoleHistoryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*consoleHistoryArgs)(nil)).Elem()
}

type ConsoleHistoryInput interface {
	pulumi.Input

	ToConsoleHistoryOutput() ConsoleHistoryOutput
	ToConsoleHistoryOutputWithContext(ctx context.Context) ConsoleHistoryOutput
}

func (*ConsoleHistory) ElementType() reflect.Type {
	return reflect.TypeOf((**ConsoleHistory)(nil)).Elem()
}

func (i *ConsoleHistory) ToConsoleHistoryOutput() ConsoleHistoryOutput {
	return i.ToConsoleHistoryOutputWithContext(context.Background())
}

func (i *ConsoleHistory) ToConsoleHistoryOutputWithContext(ctx context.Context) ConsoleHistoryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConsoleHistoryOutput)
}

// ConsoleHistoryArrayInput is an input type that accepts ConsoleHistoryArray and ConsoleHistoryArrayOutput values.
// You can construct a concrete instance of `ConsoleHistoryArrayInput` via:
//
//	ConsoleHistoryArray{ ConsoleHistoryArgs{...} }
type ConsoleHistoryArrayInput interface {
	pulumi.Input

	ToConsoleHistoryArrayOutput() ConsoleHistoryArrayOutput
	ToConsoleHistoryArrayOutputWithContext(context.Context) ConsoleHistoryArrayOutput
}

type ConsoleHistoryArray []ConsoleHistoryInput

func (ConsoleHistoryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ConsoleHistory)(nil)).Elem()
}

func (i ConsoleHistoryArray) ToConsoleHistoryArrayOutput() ConsoleHistoryArrayOutput {
	return i.ToConsoleHistoryArrayOutputWithContext(context.Background())
}

func (i ConsoleHistoryArray) ToConsoleHistoryArrayOutputWithContext(ctx context.Context) ConsoleHistoryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConsoleHistoryArrayOutput)
}

// ConsoleHistoryMapInput is an input type that accepts ConsoleHistoryMap and ConsoleHistoryMapOutput values.
// You can construct a concrete instance of `ConsoleHistoryMapInput` via:
//
//	ConsoleHistoryMap{ "key": ConsoleHistoryArgs{...} }
type ConsoleHistoryMapInput interface {
	pulumi.Input

	ToConsoleHistoryMapOutput() ConsoleHistoryMapOutput
	ToConsoleHistoryMapOutputWithContext(context.Context) ConsoleHistoryMapOutput
}

type ConsoleHistoryMap map[string]ConsoleHistoryInput

func (ConsoleHistoryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ConsoleHistory)(nil)).Elem()
}

func (i ConsoleHistoryMap) ToConsoleHistoryMapOutput() ConsoleHistoryMapOutput {
	return i.ToConsoleHistoryMapOutputWithContext(context.Background())
}

func (i ConsoleHistoryMap) ToConsoleHistoryMapOutputWithContext(ctx context.Context) ConsoleHistoryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ConsoleHistoryMapOutput)
}

type ConsoleHistoryOutput struct{ *pulumi.OutputState }

func (ConsoleHistoryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ConsoleHistory)(nil)).Elem()
}

func (o ConsoleHistoryOutput) ToConsoleHistoryOutput() ConsoleHistoryOutput {
	return o
}

func (o ConsoleHistoryOutput) ToConsoleHistoryOutputWithContext(ctx context.Context) ConsoleHistoryOutput {
	return o
}

// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
func (o ConsoleHistoryOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The OCID of the compartment.
func (o ConsoleHistoryOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o ConsoleHistoryOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o ConsoleHistoryOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o ConsoleHistoryOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the instance to get the console history from.
func (o ConsoleHistoryOutput) InstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.InstanceId }).(pulumi.StringOutput)
}

// The current state of the console history.
func (o ConsoleHistoryOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the history was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
func (o ConsoleHistoryOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ConsoleHistory) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type ConsoleHistoryArrayOutput struct{ *pulumi.OutputState }

func (ConsoleHistoryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ConsoleHistory)(nil)).Elem()
}

func (o ConsoleHistoryArrayOutput) ToConsoleHistoryArrayOutput() ConsoleHistoryArrayOutput {
	return o
}

func (o ConsoleHistoryArrayOutput) ToConsoleHistoryArrayOutputWithContext(ctx context.Context) ConsoleHistoryArrayOutput {
	return o
}

func (o ConsoleHistoryArrayOutput) Index(i pulumi.IntInput) ConsoleHistoryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ConsoleHistory {
		return vs[0].([]*ConsoleHistory)[vs[1].(int)]
	}).(ConsoleHistoryOutput)
}

type ConsoleHistoryMapOutput struct{ *pulumi.OutputState }

func (ConsoleHistoryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ConsoleHistory)(nil)).Elem()
}

func (o ConsoleHistoryMapOutput) ToConsoleHistoryMapOutput() ConsoleHistoryMapOutput {
	return o
}

func (o ConsoleHistoryMapOutput) ToConsoleHistoryMapOutputWithContext(ctx context.Context) ConsoleHistoryMapOutput {
	return o
}

func (o ConsoleHistoryMapOutput) MapIndex(k pulumi.StringInput) ConsoleHistoryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ConsoleHistory {
		return vs[0].(map[string]*ConsoleHistory)[vs[1].(string)]
	}).(ConsoleHistoryOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ConsoleHistoryInput)(nil)).Elem(), &ConsoleHistory{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConsoleHistoryArrayInput)(nil)).Elem(), ConsoleHistoryArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ConsoleHistoryMapInput)(nil)).Elem(), ConsoleHistoryMap{})
	pulumi.RegisterOutputType(ConsoleHistoryOutput{})
	pulumi.RegisterOutputType(ConsoleHistoryArrayOutput{})
	pulumi.RegisterOutputType(ConsoleHistoryMapOutput{})
}