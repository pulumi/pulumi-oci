// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package recoverymod

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Protection Policy resource in Oracle Cloud Infrastructure Recovery service.
//
// Creates a new Protection Policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/RecoveryMod"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := RecoveryMod.NewProtectionPolicy(ctx, "testProtectionPolicy", &RecoveryMod.ProtectionPolicyArgs{
//				BackupRetentionPeriodInDays: pulumi.Any(_var.Protection_policy_backup_retention_period_in_days),
//				CompartmentId:               pulumi.Any(_var.Compartment_id),
//				DisplayName:                 pulumi.Any(_var.Protection_policy_display_name),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
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
// ProtectionPolicies can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:RecoveryMod/protectionPolicy:ProtectionPolicy test_protection_policy "id"
//
// ```
type ProtectionPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) The maximum number of days to retain backups for a protected database.
	BackupRetentionPeriodInDays pulumi.IntOutput `pulumi:"backupRetentionPeriodInDays"`
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
	IsPredefinedPolicy pulumi.BoolOutput `pulumi:"isPredefinedPolicy"`
	// Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the protection policy. Allowed values are:
	// * CREATING
	// * UPDATING
	// * ACTIVE
	// * DELETING
	// * DELETED
	// * FAILED
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewProtectionPolicy registers a new resource with the given unique name, arguments, and options.
func NewProtectionPolicy(ctx *pulumi.Context,
	name string, args *ProtectionPolicyArgs, opts ...pulumi.ResourceOption) (*ProtectionPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.BackupRetentionPeriodInDays == nil {
		return nil, errors.New("invalid value for required argument 'BackupRetentionPeriodInDays'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource ProtectionPolicy
	err := ctx.RegisterResource("oci:RecoveryMod/protectionPolicy:ProtectionPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetProtectionPolicy gets an existing ProtectionPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetProtectionPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ProtectionPolicyState, opts ...pulumi.ResourceOption) (*ProtectionPolicy, error) {
	var resource ProtectionPolicy
	err := ctx.ReadResource("oci:RecoveryMod/protectionPolicy:ProtectionPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ProtectionPolicy resources.
type protectionPolicyState struct {
	// (Updatable) The maximum number of days to retain backups for a protected database.
	BackupRetentionPeriodInDays *int `pulumi:"backupRetentionPeriodInDays"`
	// (Updatable) Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
	IsPredefinedPolicy *bool `pulumi:"isPredefinedPolicy"`
	// Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the protection policy. Allowed values are:
	// * CREATING
	// * UPDATING
	// * ACTIVE
	// * DELETING
	// * DELETED
	// * FAILED
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeCreated *string `pulumi:"timeCreated"`
	// An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ProtectionPolicyState struct {
	// (Updatable) The maximum number of days to retain backups for a protected database.
	BackupRetentionPeriodInDays pulumi.IntPtrInput
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	DefinedTags pulumi.MapInput
	// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
	IsPredefinedPolicy pulumi.BoolPtrInput
	// Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the protection policy. Allowed values are:
	// * CREATING
	// * UPDATING
	// * ACTIVE
	// * DELETING
	// * DELETED
	// * FAILED
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	SystemTags pulumi.MapInput
	// An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeCreated pulumi.StringPtrInput
	// An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
	TimeUpdated pulumi.StringPtrInput
}

func (ProtectionPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*protectionPolicyState)(nil)).Elem()
}

type protectionPolicyArgs struct {
	// (Updatable) The maximum number of days to retain backups for a protected database.
	BackupRetentionPeriodInDays int `pulumi:"backupRetentionPeriodInDays"`
	// (Updatable) Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a ProtectionPolicy resource.
type ProtectionPolicyArgs struct {
	// (Updatable) The maximum number of days to retain backups for a protected database.
	BackupRetentionPeriodInDays pulumi.IntInput
	// (Updatable) Compartment Identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
	DefinedTags pulumi.MapInput
	// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
}

func (ProtectionPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*protectionPolicyArgs)(nil)).Elem()
}

type ProtectionPolicyInput interface {
	pulumi.Input

	ToProtectionPolicyOutput() ProtectionPolicyOutput
	ToProtectionPolicyOutputWithContext(ctx context.Context) ProtectionPolicyOutput
}

func (*ProtectionPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**ProtectionPolicy)(nil)).Elem()
}

func (i *ProtectionPolicy) ToProtectionPolicyOutput() ProtectionPolicyOutput {
	return i.ToProtectionPolicyOutputWithContext(context.Background())
}

func (i *ProtectionPolicy) ToProtectionPolicyOutputWithContext(ctx context.Context) ProtectionPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionPolicyOutput)
}

// ProtectionPolicyArrayInput is an input type that accepts ProtectionPolicyArray and ProtectionPolicyArrayOutput values.
// You can construct a concrete instance of `ProtectionPolicyArrayInput` via:
//
//	ProtectionPolicyArray{ ProtectionPolicyArgs{...} }
type ProtectionPolicyArrayInput interface {
	pulumi.Input

	ToProtectionPolicyArrayOutput() ProtectionPolicyArrayOutput
	ToProtectionPolicyArrayOutputWithContext(context.Context) ProtectionPolicyArrayOutput
}

type ProtectionPolicyArray []ProtectionPolicyInput

func (ProtectionPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProtectionPolicy)(nil)).Elem()
}

func (i ProtectionPolicyArray) ToProtectionPolicyArrayOutput() ProtectionPolicyArrayOutput {
	return i.ToProtectionPolicyArrayOutputWithContext(context.Background())
}

func (i ProtectionPolicyArray) ToProtectionPolicyArrayOutputWithContext(ctx context.Context) ProtectionPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionPolicyArrayOutput)
}

// ProtectionPolicyMapInput is an input type that accepts ProtectionPolicyMap and ProtectionPolicyMapOutput values.
// You can construct a concrete instance of `ProtectionPolicyMapInput` via:
//
//	ProtectionPolicyMap{ "key": ProtectionPolicyArgs{...} }
type ProtectionPolicyMapInput interface {
	pulumi.Input

	ToProtectionPolicyMapOutput() ProtectionPolicyMapOutput
	ToProtectionPolicyMapOutputWithContext(context.Context) ProtectionPolicyMapOutput
}

type ProtectionPolicyMap map[string]ProtectionPolicyInput

func (ProtectionPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProtectionPolicy)(nil)).Elem()
}

func (i ProtectionPolicyMap) ToProtectionPolicyMapOutput() ProtectionPolicyMapOutput {
	return i.ToProtectionPolicyMapOutputWithContext(context.Background())
}

func (i ProtectionPolicyMap) ToProtectionPolicyMapOutputWithContext(ctx context.Context) ProtectionPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionPolicyMapOutput)
}

type ProtectionPolicyOutput struct{ *pulumi.OutputState }

func (ProtectionPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ProtectionPolicy)(nil)).Elem()
}

func (o ProtectionPolicyOutput) ToProtectionPolicyOutput() ProtectionPolicyOutput {
	return o
}

func (o ProtectionPolicyOutput) ToProtectionPolicyOutputWithContext(ctx context.Context) ProtectionPolicyOutput {
	return o
}

// (Updatable) The maximum number of days to retain backups for a protected database.
func (o ProtectionPolicyOutput) BackupRetentionPeriodInDays() pulumi.IntOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.IntOutput { return v.BackupRetentionPeriodInDays }).(pulumi.IntOutput)
}

// (Updatable) Compartment Identifier
func (o ProtectionPolicyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
func (o ProtectionPolicyOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A user provided name for the protection policy. The 'displayName' does not have to be unique, and it can be modified. Avoid entering confidential information.
func (o ProtectionPolicyOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o ProtectionPolicyOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
func (o ProtectionPolicyOutput) IsPredefinedPolicy() pulumi.BoolOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.BoolOutput { return v.IsPredefinedPolicy }).(pulumi.BoolOutput)
}

// Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
func (o ProtectionPolicyOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current state of the protection policy. Allowed values are:
// * CREATING
// * UPDATING
// * ACTIVE
// * DELETING
// * DELETED
// * FAILED
func (o ProtectionPolicyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
func (o ProtectionPolicyOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
func (o ProtectionPolicyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
func (o ProtectionPolicyOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionPolicy) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ProtectionPolicyArrayOutput struct{ *pulumi.OutputState }

func (ProtectionPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProtectionPolicy)(nil)).Elem()
}

func (o ProtectionPolicyArrayOutput) ToProtectionPolicyArrayOutput() ProtectionPolicyArrayOutput {
	return o
}

func (o ProtectionPolicyArrayOutput) ToProtectionPolicyArrayOutputWithContext(ctx context.Context) ProtectionPolicyArrayOutput {
	return o
}

func (o ProtectionPolicyArrayOutput) Index(i pulumi.IntInput) ProtectionPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ProtectionPolicy {
		return vs[0].([]*ProtectionPolicy)[vs[1].(int)]
	}).(ProtectionPolicyOutput)
}

type ProtectionPolicyMapOutput struct{ *pulumi.OutputState }

func (ProtectionPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProtectionPolicy)(nil)).Elem()
}

func (o ProtectionPolicyMapOutput) ToProtectionPolicyMapOutput() ProtectionPolicyMapOutput {
	return o
}

func (o ProtectionPolicyMapOutput) ToProtectionPolicyMapOutputWithContext(ctx context.Context) ProtectionPolicyMapOutput {
	return o
}

func (o ProtectionPolicyMapOutput) MapIndex(k pulumi.StringInput) ProtectionPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ProtectionPolicy {
		return vs[0].(map[string]*ProtectionPolicy)[vs[1].(string)]
	}).(ProtectionPolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionPolicyInput)(nil)).Elem(), &ProtectionPolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionPolicyArrayInput)(nil)).Elem(), ProtectionPolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionPolicyMapInput)(nil)).Elem(), ProtectionPolicyMap{})
	pulumi.RegisterOutputType(ProtectionPolicyOutput{})
	pulumi.RegisterOutputType(ProtectionPolicyArrayOutput{})
	pulumi.RegisterOutputType(ProtectionPolicyMapOutput{})
}