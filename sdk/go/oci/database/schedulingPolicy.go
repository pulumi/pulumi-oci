// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Scheduling Policy resource in Oracle Cloud Infrastructure Database service.
//
// Creates a Scheduling Policy resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.NewSchedulingPolicy(ctx, "test_scheduling_policy", &database.SchedulingPolicyArgs{
//				Cadence:       pulumi.Any(schedulingPolicyCadence),
//				CompartmentId: pulumi.Any(compartmentId),
//				DisplayName:   pulumi.Any(schedulingPolicyDisplayName),
//				CadenceStartMonth: &database.SchedulingPolicyCadenceStartMonthArgs{
//					Name: pulumi.Any(schedulingPolicyCadenceStartMonthName),
//				},
//				DefinedTags: pulumi.Any(schedulingPolicyDefinedTags),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
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
// SchedulingPolicies can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Database/schedulingPolicy:SchedulingPolicy test_scheduling_policy "id"
// ```
type SchedulingPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) The cadence period.
	Cadence pulumi.StringOutput `pulumi:"cadence"`
	// (Updatable) Start of the month to be followed during the cadence period.
	CadenceStartMonth SchedulingPolicyCadenceStartMonthOutput `pulumi:"cadenceStartMonth"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the Scheduling Policy was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
	TimeNextWindowStarts pulumi.StringOutput `pulumi:"timeNextWindowStarts"`
	// The last date and time that the Scheduling Policy was updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewSchedulingPolicy registers a new resource with the given unique name, arguments, and options.
func NewSchedulingPolicy(ctx *pulumi.Context,
	name string, args *SchedulingPolicyArgs, opts ...pulumi.ResourceOption) (*SchedulingPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Cadence == nil {
		return nil, errors.New("invalid value for required argument 'Cadence'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource SchedulingPolicy
	err := ctx.RegisterResource("oci:Database/schedulingPolicy:SchedulingPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSchedulingPolicy gets an existing SchedulingPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSchedulingPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SchedulingPolicyState, opts ...pulumi.ResourceOption) (*SchedulingPolicy, error) {
	var resource SchedulingPolicy
	err := ctx.ReadResource("oci:Database/schedulingPolicy:SchedulingPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SchedulingPolicy resources.
type schedulingPolicyState struct {
	// (Updatable) The cadence period.
	Cadence *string `pulumi:"cadence"`
	// (Updatable) Start of the month to be followed during the cadence period.
	CadenceStartMonth *SchedulingPolicyCadenceStartMonth `pulumi:"cadenceStartMonth"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
	State *string `pulumi:"state"`
	// The date and time the Scheduling Policy was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
	TimeNextWindowStarts *string `pulumi:"timeNextWindowStarts"`
	// The last date and time that the Scheduling Policy was updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type SchedulingPolicyState struct {
	// (Updatable) The cadence period.
	Cadence pulumi.StringPtrInput
	// (Updatable) Start of the month to be followed during the cadence period.
	CadenceStartMonth SchedulingPolicyCadenceStartMonthPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
	State pulumi.StringPtrInput
	// The date and time the Scheduling Policy was created.
	TimeCreated pulumi.StringPtrInput
	// The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
	TimeNextWindowStarts pulumi.StringPtrInput
	// The last date and time that the Scheduling Policy was updated.
	TimeUpdated pulumi.StringPtrInput
}

func (SchedulingPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*schedulingPolicyState)(nil)).Elem()
}

type schedulingPolicyArgs struct {
	// (Updatable) The cadence period.
	Cadence string `pulumi:"cadence"`
	// (Updatable) Start of the month to be followed during the cadence period.
	CadenceStartMonth *SchedulingPolicyCadenceStartMonth `pulumi:"cadenceStartMonth"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a SchedulingPolicy resource.
type SchedulingPolicyArgs struct {
	// (Updatable) The cadence period.
	Cadence pulumi.StringInput
	// (Updatable) Start of the month to be followed during the cadence period.
	CadenceStartMonth SchedulingPolicyCadenceStartMonthPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (SchedulingPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*schedulingPolicyArgs)(nil)).Elem()
}

type SchedulingPolicyInput interface {
	pulumi.Input

	ToSchedulingPolicyOutput() SchedulingPolicyOutput
	ToSchedulingPolicyOutputWithContext(ctx context.Context) SchedulingPolicyOutput
}

func (*SchedulingPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**SchedulingPolicy)(nil)).Elem()
}

func (i *SchedulingPolicy) ToSchedulingPolicyOutput() SchedulingPolicyOutput {
	return i.ToSchedulingPolicyOutputWithContext(context.Background())
}

func (i *SchedulingPolicy) ToSchedulingPolicyOutputWithContext(ctx context.Context) SchedulingPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SchedulingPolicyOutput)
}

// SchedulingPolicyArrayInput is an input type that accepts SchedulingPolicyArray and SchedulingPolicyArrayOutput values.
// You can construct a concrete instance of `SchedulingPolicyArrayInput` via:
//
//	SchedulingPolicyArray{ SchedulingPolicyArgs{...} }
type SchedulingPolicyArrayInput interface {
	pulumi.Input

	ToSchedulingPolicyArrayOutput() SchedulingPolicyArrayOutput
	ToSchedulingPolicyArrayOutputWithContext(context.Context) SchedulingPolicyArrayOutput
}

type SchedulingPolicyArray []SchedulingPolicyInput

func (SchedulingPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SchedulingPolicy)(nil)).Elem()
}

func (i SchedulingPolicyArray) ToSchedulingPolicyArrayOutput() SchedulingPolicyArrayOutput {
	return i.ToSchedulingPolicyArrayOutputWithContext(context.Background())
}

func (i SchedulingPolicyArray) ToSchedulingPolicyArrayOutputWithContext(ctx context.Context) SchedulingPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SchedulingPolicyArrayOutput)
}

// SchedulingPolicyMapInput is an input type that accepts SchedulingPolicyMap and SchedulingPolicyMapOutput values.
// You can construct a concrete instance of `SchedulingPolicyMapInput` via:
//
//	SchedulingPolicyMap{ "key": SchedulingPolicyArgs{...} }
type SchedulingPolicyMapInput interface {
	pulumi.Input

	ToSchedulingPolicyMapOutput() SchedulingPolicyMapOutput
	ToSchedulingPolicyMapOutputWithContext(context.Context) SchedulingPolicyMapOutput
}

type SchedulingPolicyMap map[string]SchedulingPolicyInput

func (SchedulingPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SchedulingPolicy)(nil)).Elem()
}

func (i SchedulingPolicyMap) ToSchedulingPolicyMapOutput() SchedulingPolicyMapOutput {
	return i.ToSchedulingPolicyMapOutputWithContext(context.Background())
}

func (i SchedulingPolicyMap) ToSchedulingPolicyMapOutputWithContext(ctx context.Context) SchedulingPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SchedulingPolicyMapOutput)
}

type SchedulingPolicyOutput struct{ *pulumi.OutputState }

func (SchedulingPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SchedulingPolicy)(nil)).Elem()
}

func (o SchedulingPolicyOutput) ToSchedulingPolicyOutput() SchedulingPolicyOutput {
	return o
}

func (o SchedulingPolicyOutput) ToSchedulingPolicyOutputWithContext(ctx context.Context) SchedulingPolicyOutput {
	return o
}

// (Updatable) The cadence period.
func (o SchedulingPolicyOutput) Cadence() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.Cadence }).(pulumi.StringOutput)
}

// (Updatable) Start of the month to be followed during the cadence period.
func (o SchedulingPolicyOutput) CadenceStartMonth() SchedulingPolicyCadenceStartMonthOutput {
	return o.ApplyT(func(v *SchedulingPolicy) SchedulingPolicyCadenceStartMonthOutput { return v.CadenceStartMonth }).(SchedulingPolicyCadenceStartMonthOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o SchedulingPolicyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o SchedulingPolicyOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
func (o SchedulingPolicyOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o SchedulingPolicyOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Additional information about the current lifecycle state.
func (o SchedulingPolicyOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
func (o SchedulingPolicyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the Scheduling Policy was created.
func (o SchedulingPolicyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
func (o SchedulingPolicyOutput) TimeNextWindowStarts() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.TimeNextWindowStarts }).(pulumi.StringOutput)
}

// The last date and time that the Scheduling Policy was updated.
func (o SchedulingPolicyOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *SchedulingPolicy) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type SchedulingPolicyArrayOutput struct{ *pulumi.OutputState }

func (SchedulingPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SchedulingPolicy)(nil)).Elem()
}

func (o SchedulingPolicyArrayOutput) ToSchedulingPolicyArrayOutput() SchedulingPolicyArrayOutput {
	return o
}

func (o SchedulingPolicyArrayOutput) ToSchedulingPolicyArrayOutputWithContext(ctx context.Context) SchedulingPolicyArrayOutput {
	return o
}

func (o SchedulingPolicyArrayOutput) Index(i pulumi.IntInput) SchedulingPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SchedulingPolicy {
		return vs[0].([]*SchedulingPolicy)[vs[1].(int)]
	}).(SchedulingPolicyOutput)
}

type SchedulingPolicyMapOutput struct{ *pulumi.OutputState }

func (SchedulingPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SchedulingPolicy)(nil)).Elem()
}

func (o SchedulingPolicyMapOutput) ToSchedulingPolicyMapOutput() SchedulingPolicyMapOutput {
	return o
}

func (o SchedulingPolicyMapOutput) ToSchedulingPolicyMapOutputWithContext(ctx context.Context) SchedulingPolicyMapOutput {
	return o
}

func (o SchedulingPolicyMapOutput) MapIndex(k pulumi.StringInput) SchedulingPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SchedulingPolicy {
		return vs[0].(map[string]*SchedulingPolicy)[vs[1].(string)]
	}).(SchedulingPolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SchedulingPolicyInput)(nil)).Elem(), &SchedulingPolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*SchedulingPolicyArrayInput)(nil)).Elem(), SchedulingPolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SchedulingPolicyMapInput)(nil)).Elem(), SchedulingPolicyMap{})
	pulumi.RegisterOutputType(SchedulingPolicyOutput{})
	pulumi.RegisterOutputType(SchedulingPolicyArrayOutput{})
	pulumi.RegisterOutputType(SchedulingPolicyMapOutput{})
}
