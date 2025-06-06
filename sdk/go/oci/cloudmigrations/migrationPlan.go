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

// This resource provides the Migration Plan resource in Oracle Cloud Infrastructure Cloud Migrations service.
//
// Creates a migration plan.
//
// ## Import
//
// MigrationPlans can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudMigrations/migrationPlan:MigrationPlan test_migration_plan "id"
// ```
type MigrationPlan struct {
	pulumi.CustomResourceState

	// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
	CalculatedLimits pulumi.StringMapOutput `pulumi:"calculatedLimits"`
	// (Updatable) Compartment identifier
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Migration plan identifier
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the associated migration.
	MigrationId pulumi.StringOutput `pulumi:"migrationId"`
	// Status of the migration plan.
	MigrationPlanStats MigrationPlanMigrationPlanStatArrayOutput `pulumi:"migrationPlanStats"`
	// OCID of the referenced ORM job.
	ReferenceToRmsStack pulumi.StringOutput `pulumi:"referenceToRmsStack"`
	// Source migraiton plan ID to be cloned.
	SourceMigrationPlanId pulumi.StringOutput `pulumi:"sourceMigrationPlanId"`
	// The current state of the migration plan.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) List of strategies for the resources to be migrated.
	Strategies MigrationPlanStrategyArrayOutput `pulumi:"strategies"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// (Updatable) List of target environments.
	TargetEnvironments MigrationPlanTargetEnvironmentArrayOutput `pulumi:"targetEnvironments"`
	// The time when the migration plan was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the migration plan was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewMigrationPlan registers a new resource with the given unique name, arguments, and options.
func NewMigrationPlan(ctx *pulumi.Context,
	name string, args *MigrationPlanArgs, opts ...pulumi.ResourceOption) (*MigrationPlan, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.MigrationId == nil {
		return nil, errors.New("invalid value for required argument 'MigrationId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MigrationPlan
	err := ctx.RegisterResource("oci:CloudMigrations/migrationPlan:MigrationPlan", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMigrationPlan gets an existing MigrationPlan resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMigrationPlan(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MigrationPlanState, opts ...pulumi.ResourceOption) (*MigrationPlan, error) {
	var resource MigrationPlan
	err := ctx.ReadResource("oci:CloudMigrations/migrationPlan:MigrationPlan", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MigrationPlan resources.
type migrationPlanState struct {
	// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
	CalculatedLimits map[string]string `pulumi:"calculatedLimits"`
	// (Updatable) Compartment identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Migration plan identifier
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the associated migration.
	MigrationId *string `pulumi:"migrationId"`
	// Status of the migration plan.
	MigrationPlanStats []MigrationPlanMigrationPlanStat `pulumi:"migrationPlanStats"`
	// OCID of the referenced ORM job.
	ReferenceToRmsStack *string `pulumi:"referenceToRmsStack"`
	// Source migraiton plan ID to be cloned.
	SourceMigrationPlanId *string `pulumi:"sourceMigrationPlanId"`
	// The current state of the migration plan.
	State *string `pulumi:"state"`
	// (Updatable) List of strategies for the resources to be migrated.
	Strategies []MigrationPlanStrategy `pulumi:"strategies"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// (Updatable) List of target environments.
	TargetEnvironments []MigrationPlanTargetEnvironment `pulumi:"targetEnvironments"`
	// The time when the migration plan was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the migration plan was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type MigrationPlanState struct {
	// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
	CalculatedLimits pulumi.StringMapInput
	// (Updatable) Compartment identifier
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Migration plan identifier
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the associated migration.
	MigrationId pulumi.StringPtrInput
	// Status of the migration plan.
	MigrationPlanStats MigrationPlanMigrationPlanStatArrayInput
	// OCID of the referenced ORM job.
	ReferenceToRmsStack pulumi.StringPtrInput
	// Source migraiton plan ID to be cloned.
	SourceMigrationPlanId pulumi.StringPtrInput
	// The current state of the migration plan.
	State pulumi.StringPtrInput
	// (Updatable) List of strategies for the resources to be migrated.
	Strategies MigrationPlanStrategyArrayInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// (Updatable) List of target environments.
	TargetEnvironments MigrationPlanTargetEnvironmentArrayInput
	// The time when the migration plan was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the migration plan was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (MigrationPlanState) ElementType() reflect.Type {
	return reflect.TypeOf((*migrationPlanState)(nil)).Elem()
}

type migrationPlanArgs struct {
	// (Updatable) Compartment identifier
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Migration plan identifier
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the associated migration.
	MigrationId string `pulumi:"migrationId"`
	// Source migraiton plan ID to be cloned.
	SourceMigrationPlanId *string `pulumi:"sourceMigrationPlanId"`
	// (Updatable) List of strategies for the resources to be migrated.
	Strategies []MigrationPlanStrategy `pulumi:"strategies"`
	// (Updatable) List of target environments.
	TargetEnvironments []MigrationPlanTargetEnvironment `pulumi:"targetEnvironments"`
}

// The set of arguments for constructing a MigrationPlan resource.
type MigrationPlanArgs struct {
	// (Updatable) Compartment identifier
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Migration plan identifier
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The OCID of the associated migration.
	MigrationId pulumi.StringInput
	// Source migraiton plan ID to be cloned.
	SourceMigrationPlanId pulumi.StringPtrInput
	// (Updatable) List of strategies for the resources to be migrated.
	Strategies MigrationPlanStrategyArrayInput
	// (Updatable) List of target environments.
	TargetEnvironments MigrationPlanTargetEnvironmentArrayInput
}

func (MigrationPlanArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*migrationPlanArgs)(nil)).Elem()
}

type MigrationPlanInput interface {
	pulumi.Input

	ToMigrationPlanOutput() MigrationPlanOutput
	ToMigrationPlanOutputWithContext(ctx context.Context) MigrationPlanOutput
}

func (*MigrationPlan) ElementType() reflect.Type {
	return reflect.TypeOf((**MigrationPlan)(nil)).Elem()
}

func (i *MigrationPlan) ToMigrationPlanOutput() MigrationPlanOutput {
	return i.ToMigrationPlanOutputWithContext(context.Background())
}

func (i *MigrationPlan) ToMigrationPlanOutputWithContext(ctx context.Context) MigrationPlanOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationPlanOutput)
}

// MigrationPlanArrayInput is an input type that accepts MigrationPlanArray and MigrationPlanArrayOutput values.
// You can construct a concrete instance of `MigrationPlanArrayInput` via:
//
//	MigrationPlanArray{ MigrationPlanArgs{...} }
type MigrationPlanArrayInput interface {
	pulumi.Input

	ToMigrationPlanArrayOutput() MigrationPlanArrayOutput
	ToMigrationPlanArrayOutputWithContext(context.Context) MigrationPlanArrayOutput
}

type MigrationPlanArray []MigrationPlanInput

func (MigrationPlanArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MigrationPlan)(nil)).Elem()
}

func (i MigrationPlanArray) ToMigrationPlanArrayOutput() MigrationPlanArrayOutput {
	return i.ToMigrationPlanArrayOutputWithContext(context.Background())
}

func (i MigrationPlanArray) ToMigrationPlanArrayOutputWithContext(ctx context.Context) MigrationPlanArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationPlanArrayOutput)
}

// MigrationPlanMapInput is an input type that accepts MigrationPlanMap and MigrationPlanMapOutput values.
// You can construct a concrete instance of `MigrationPlanMapInput` via:
//
//	MigrationPlanMap{ "key": MigrationPlanArgs{...} }
type MigrationPlanMapInput interface {
	pulumi.Input

	ToMigrationPlanMapOutput() MigrationPlanMapOutput
	ToMigrationPlanMapOutputWithContext(context.Context) MigrationPlanMapOutput
}

type MigrationPlanMap map[string]MigrationPlanInput

func (MigrationPlanMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MigrationPlan)(nil)).Elem()
}

func (i MigrationPlanMap) ToMigrationPlanMapOutput() MigrationPlanMapOutput {
	return i.ToMigrationPlanMapOutputWithContext(context.Background())
}

func (i MigrationPlanMap) ToMigrationPlanMapOutputWithContext(ctx context.Context) MigrationPlanMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MigrationPlanMapOutput)
}

type MigrationPlanOutput struct{ *pulumi.OutputState }

func (MigrationPlanOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MigrationPlan)(nil)).Elem()
}

func (o MigrationPlanOutput) ToMigrationPlanOutput() MigrationPlanOutput {
	return o
}

func (o MigrationPlanOutput) ToMigrationPlanOutputWithContext(ctx context.Context) MigrationPlanOutput {
	return o
}

// Limits of the resources that are needed for migration. Example: {"BlockVolume": 2, "VCN": 1}
func (o MigrationPlanOutput) CalculatedLimits() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringMapOutput { return v.CalculatedLimits }).(pulumi.StringMapOutput)
}

// (Updatable) Compartment identifier
func (o MigrationPlanOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o MigrationPlanOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Migration plan identifier
func (o MigrationPlanOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
func (o MigrationPlanOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
func (o MigrationPlanOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the associated migration.
func (o MigrationPlanOutput) MigrationId() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.MigrationId }).(pulumi.StringOutput)
}

// Status of the migration plan.
func (o MigrationPlanOutput) MigrationPlanStats() MigrationPlanMigrationPlanStatArrayOutput {
	return o.ApplyT(func(v *MigrationPlan) MigrationPlanMigrationPlanStatArrayOutput { return v.MigrationPlanStats }).(MigrationPlanMigrationPlanStatArrayOutput)
}

// OCID of the referenced ORM job.
func (o MigrationPlanOutput) ReferenceToRmsStack() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.ReferenceToRmsStack }).(pulumi.StringOutput)
}

// Source migraiton plan ID to be cloned.
func (o MigrationPlanOutput) SourceMigrationPlanId() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.SourceMigrationPlanId }).(pulumi.StringOutput)
}

// The current state of the migration plan.
func (o MigrationPlanOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) List of strategies for the resources to be migrated.
func (o MigrationPlanOutput) Strategies() MigrationPlanStrategyArrayOutput {
	return o.ApplyT(func(v *MigrationPlan) MigrationPlanStrategyArrayOutput { return v.Strategies }).(MigrationPlanStrategyArrayOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o MigrationPlanOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// (Updatable) List of target environments.
func (o MigrationPlanOutput) TargetEnvironments() MigrationPlanTargetEnvironmentArrayOutput {
	return o.ApplyT(func(v *MigrationPlan) MigrationPlanTargetEnvironmentArrayOutput { return v.TargetEnvironments }).(MigrationPlanTargetEnvironmentArrayOutput)
}

// The time when the migration plan was created. An RFC3339 formatted datetime string.
func (o MigrationPlanOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the migration plan was updated. An RFC3339 formatted datetime string.
func (o MigrationPlanOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *MigrationPlan) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type MigrationPlanArrayOutput struct{ *pulumi.OutputState }

func (MigrationPlanArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MigrationPlan)(nil)).Elem()
}

func (o MigrationPlanArrayOutput) ToMigrationPlanArrayOutput() MigrationPlanArrayOutput {
	return o
}

func (o MigrationPlanArrayOutput) ToMigrationPlanArrayOutputWithContext(ctx context.Context) MigrationPlanArrayOutput {
	return o
}

func (o MigrationPlanArrayOutput) Index(i pulumi.IntInput) MigrationPlanOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MigrationPlan {
		return vs[0].([]*MigrationPlan)[vs[1].(int)]
	}).(MigrationPlanOutput)
}

type MigrationPlanMapOutput struct{ *pulumi.OutputState }

func (MigrationPlanMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MigrationPlan)(nil)).Elem()
}

func (o MigrationPlanMapOutput) ToMigrationPlanMapOutput() MigrationPlanMapOutput {
	return o
}

func (o MigrationPlanMapOutput) ToMigrationPlanMapOutputWithContext(ctx context.Context) MigrationPlanMapOutput {
	return o
}

func (o MigrationPlanMapOutput) MapIndex(k pulumi.StringInput) MigrationPlanOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MigrationPlan {
		return vs[0].(map[string]*MigrationPlan)[vs[1].(string)]
	}).(MigrationPlanOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MigrationPlanInput)(nil)).Elem(), &MigrationPlan{})
	pulumi.RegisterInputType(reflect.TypeOf((*MigrationPlanArrayInput)(nil)).Elem(), MigrationPlanArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MigrationPlanMapInput)(nil)).Elem(), MigrationPlanMap{})
	pulumi.RegisterOutputType(MigrationPlanOutput{})
	pulumi.RegisterOutputType(MigrationPlanArrayOutput{})
	pulumi.RegisterOutputType(MigrationPlanMapOutput{})
}
