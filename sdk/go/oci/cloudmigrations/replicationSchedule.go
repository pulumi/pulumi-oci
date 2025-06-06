// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudmigrations

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Replication Schedule resource in Oracle Cloud Infrastructure Cloud Migrations service.
//
// Creates a replication schedule.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudmigrations"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudmigrations.NewReplicationSchedule(ctx, "test_replication_schedule", &cloudmigrations.ReplicationScheduleArgs{
//				CompartmentId:        pulumi.Any(compartmentId),
//				DisplayName:          pulumi.Any(replicationScheduleDisplayName),
//				ExecutionRecurrences: pulumi.Any(replicationScheduleExecutionRecurrences),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
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
// ReplicationSchedules can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudMigrations/replicationSchedule:ReplicationSchedule test_replication_schedule "id"
// ```
type ReplicationSchedule struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Recurrence specification for replication schedule execution.
	ExecutionRecurrences pulumi.StringOutput `pulumi:"executionRecurrences"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The detailed state of the replication schedule.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Current state of the replication schedule.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when the replication schedule was created in RFC3339 format.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the replication schedule was last updated in RFC3339 format.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewReplicationSchedule registers a new resource with the given unique name, arguments, and options.
func NewReplicationSchedule(ctx *pulumi.Context,
	name string, args *ReplicationScheduleArgs, opts ...pulumi.ResourceOption) (*ReplicationSchedule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.ExecutionRecurrences == nil {
		return nil, errors.New("invalid value for required argument 'ExecutionRecurrences'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ReplicationSchedule
	err := ctx.RegisterResource("oci:CloudMigrations/replicationSchedule:ReplicationSchedule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetReplicationSchedule gets an existing ReplicationSchedule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetReplicationSchedule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ReplicationScheduleState, opts ...pulumi.ResourceOption) (*ReplicationSchedule, error) {
	var resource ReplicationSchedule
	err := ctx.ReadResource("oci:CloudMigrations/replicationSchedule:ReplicationSchedule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ReplicationSchedule resources.
type replicationScheduleState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Recurrence specification for replication schedule execution.
	ExecutionRecurrences *string `pulumi:"executionRecurrences"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The detailed state of the replication schedule.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Current state of the replication schedule.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the replication schedule was created in RFC3339 format.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the replication schedule was last updated in RFC3339 format.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ReplicationScheduleState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Recurrence specification for replication schedule execution.
	ExecutionRecurrences pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The detailed state of the replication schedule.
	LifecycleDetails pulumi.StringPtrInput
	// Current state of the replication schedule.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time when the replication schedule was created in RFC3339 format.
	TimeCreated pulumi.StringPtrInput
	// The time when the replication schedule was last updated in RFC3339 format.
	TimeUpdated pulumi.StringPtrInput
}

func (ReplicationScheduleState) ElementType() reflect.Type {
	return reflect.TypeOf((*replicationScheduleState)(nil)).Elem()
}

type replicationScheduleArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Recurrence specification for replication schedule execution.
	ExecutionRecurrences string `pulumi:"executionRecurrences"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a ReplicationSchedule resource.
type ReplicationScheduleArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Recurrence specification for replication schedule execution.
	ExecutionRecurrences pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (ReplicationScheduleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*replicationScheduleArgs)(nil)).Elem()
}

type ReplicationScheduleInput interface {
	pulumi.Input

	ToReplicationScheduleOutput() ReplicationScheduleOutput
	ToReplicationScheduleOutputWithContext(ctx context.Context) ReplicationScheduleOutput
}

func (*ReplicationSchedule) ElementType() reflect.Type {
	return reflect.TypeOf((**ReplicationSchedule)(nil)).Elem()
}

func (i *ReplicationSchedule) ToReplicationScheduleOutput() ReplicationScheduleOutput {
	return i.ToReplicationScheduleOutputWithContext(context.Background())
}

func (i *ReplicationSchedule) ToReplicationScheduleOutputWithContext(ctx context.Context) ReplicationScheduleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationScheduleOutput)
}

// ReplicationScheduleArrayInput is an input type that accepts ReplicationScheduleArray and ReplicationScheduleArrayOutput values.
// You can construct a concrete instance of `ReplicationScheduleArrayInput` via:
//
//	ReplicationScheduleArray{ ReplicationScheduleArgs{...} }
type ReplicationScheduleArrayInput interface {
	pulumi.Input

	ToReplicationScheduleArrayOutput() ReplicationScheduleArrayOutput
	ToReplicationScheduleArrayOutputWithContext(context.Context) ReplicationScheduleArrayOutput
}

type ReplicationScheduleArray []ReplicationScheduleInput

func (ReplicationScheduleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ReplicationSchedule)(nil)).Elem()
}

func (i ReplicationScheduleArray) ToReplicationScheduleArrayOutput() ReplicationScheduleArrayOutput {
	return i.ToReplicationScheduleArrayOutputWithContext(context.Background())
}

func (i ReplicationScheduleArray) ToReplicationScheduleArrayOutputWithContext(ctx context.Context) ReplicationScheduleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationScheduleArrayOutput)
}

// ReplicationScheduleMapInput is an input type that accepts ReplicationScheduleMap and ReplicationScheduleMapOutput values.
// You can construct a concrete instance of `ReplicationScheduleMapInput` via:
//
//	ReplicationScheduleMap{ "key": ReplicationScheduleArgs{...} }
type ReplicationScheduleMapInput interface {
	pulumi.Input

	ToReplicationScheduleMapOutput() ReplicationScheduleMapOutput
	ToReplicationScheduleMapOutputWithContext(context.Context) ReplicationScheduleMapOutput
}

type ReplicationScheduleMap map[string]ReplicationScheduleInput

func (ReplicationScheduleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ReplicationSchedule)(nil)).Elem()
}

func (i ReplicationScheduleMap) ToReplicationScheduleMapOutput() ReplicationScheduleMapOutput {
	return i.ToReplicationScheduleMapOutputWithContext(context.Background())
}

func (i ReplicationScheduleMap) ToReplicationScheduleMapOutputWithContext(ctx context.Context) ReplicationScheduleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationScheduleMapOutput)
}

type ReplicationScheduleOutput struct{ *pulumi.OutputState }

func (ReplicationScheduleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ReplicationSchedule)(nil)).Elem()
}

func (o ReplicationScheduleOutput) ToReplicationScheduleOutput() ReplicationScheduleOutput {
	return o
}

func (o ReplicationScheduleOutput) ToReplicationScheduleOutputWithContext(ctx context.Context) ReplicationScheduleOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the replication schedule should be created.
func (o ReplicationScheduleOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o ReplicationScheduleOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name for a replication schedule. Does not have to be unique, and is mutable. Avoid entering confidential information.
func (o ReplicationScheduleOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Recurrence specification for replication schedule execution.
func (o ReplicationScheduleOutput) ExecutionRecurrences() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.ExecutionRecurrences }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ReplicationScheduleOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The detailed state of the replication schedule.
func (o ReplicationScheduleOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Current state of the replication schedule.
func (o ReplicationScheduleOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ReplicationScheduleOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the replication schedule was created in RFC3339 format.
func (o ReplicationScheduleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the replication schedule was last updated in RFC3339 format.
func (o ReplicationScheduleOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ReplicationSchedule) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ReplicationScheduleArrayOutput struct{ *pulumi.OutputState }

func (ReplicationScheduleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ReplicationSchedule)(nil)).Elem()
}

func (o ReplicationScheduleArrayOutput) ToReplicationScheduleArrayOutput() ReplicationScheduleArrayOutput {
	return o
}

func (o ReplicationScheduleArrayOutput) ToReplicationScheduleArrayOutputWithContext(ctx context.Context) ReplicationScheduleArrayOutput {
	return o
}

func (o ReplicationScheduleArrayOutput) Index(i pulumi.IntInput) ReplicationScheduleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ReplicationSchedule {
		return vs[0].([]*ReplicationSchedule)[vs[1].(int)]
	}).(ReplicationScheduleOutput)
}

type ReplicationScheduleMapOutput struct{ *pulumi.OutputState }

func (ReplicationScheduleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ReplicationSchedule)(nil)).Elem()
}

func (o ReplicationScheduleMapOutput) ToReplicationScheduleMapOutput() ReplicationScheduleMapOutput {
	return o
}

func (o ReplicationScheduleMapOutput) ToReplicationScheduleMapOutputWithContext(ctx context.Context) ReplicationScheduleMapOutput {
	return o
}

func (o ReplicationScheduleMapOutput) MapIndex(k pulumi.StringInput) ReplicationScheduleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ReplicationSchedule {
		return vs[0].(map[string]*ReplicationSchedule)[vs[1].(string)]
	}).(ReplicationScheduleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationScheduleInput)(nil)).Elem(), &ReplicationSchedule{})
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationScheduleArrayInput)(nil)).Elem(), ReplicationScheduleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationScheduleMapInput)(nil)).Elem(), ReplicationScheduleMap{})
	pulumi.RegisterOutputType(ReplicationScheduleOutput{})
	pulumi.RegisterOutputType(ReplicationScheduleArrayOutput{})
	pulumi.RegisterOutputType(ReplicationScheduleMapOutput{})
}
