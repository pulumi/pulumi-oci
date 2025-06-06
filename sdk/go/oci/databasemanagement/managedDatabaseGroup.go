// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.
//
// Creates a Managed Database Group. The group does not contain any
// Managed Databases when it is created, and they must be added later.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.NewManagedDatabaseGroup(ctx, "test_managed_database_group", &databasemanagement.ManagedDatabaseGroupArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				Name:          pulumi.Any(managedDatabaseGroupName),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				Description: pulumi.Any(managedDatabaseGroupDescription),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				ManagedDatabases: databasemanagement.ManagedDatabaseGroupManagedDatabaseArray{
//					&databasemanagement.ManagedDatabaseGroupManagedDatabaseArgs{
//						Id: pulumi.Any(managedDatabaseId),
//					},
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
// ManagedDatabaseGroups can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup test_managed_database_group "id"
// ```
type ManagedDatabaseGroup struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The information specified by the user about the Managed Database Group.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
	ManagedDatabases ManagedDatabaseGroupManagedDatabaseArrayOutput `pulumi:"managedDatabases"`
	// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
	Name pulumi.StringOutput `pulumi:"name"`
	// The current lifecycle state of the Managed Database Group.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the Managed Database Group was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the Managed Database Group was last updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewManagedDatabaseGroup registers a new resource with the given unique name, arguments, and options.
func NewManagedDatabaseGroup(ctx *pulumi.Context,
	name string, args *ManagedDatabaseGroupArgs, opts ...pulumi.ResourceOption) (*ManagedDatabaseGroup, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ManagedDatabaseGroup
	err := ctx.RegisterResource("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetManagedDatabaseGroup gets an existing ManagedDatabaseGroup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetManagedDatabaseGroup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ManagedDatabaseGroupState, opts ...pulumi.ResourceOption) (*ManagedDatabaseGroup, error) {
	var resource ManagedDatabaseGroup
	err := ctx.ReadResource("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ManagedDatabaseGroup resources.
type managedDatabaseGroupState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The information specified by the user about the Managed Database Group.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
	ManagedDatabases []ManagedDatabaseGroupManagedDatabase `pulumi:"managedDatabases"`
	// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
	Name *string `pulumi:"name"`
	// The current lifecycle state of the Managed Database Group.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the Managed Database Group was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the Managed Database Group was last updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type ManagedDatabaseGroupState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The information specified by the user about the Managed Database Group.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
	ManagedDatabases ManagedDatabaseGroupManagedDatabaseArrayInput
	// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
	Name pulumi.StringPtrInput
	// The current lifecycle state of the Managed Database Group.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the Managed Database Group was created.
	TimeCreated pulumi.StringPtrInput
	// The date and time the Managed Database Group was last updated.
	TimeUpdated pulumi.StringPtrInput
}

func (ManagedDatabaseGroupState) ElementType() reflect.Type {
	return reflect.TypeOf((*managedDatabaseGroupState)(nil)).Elem()
}

type managedDatabaseGroupArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The information specified by the user about the Managed Database Group.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
	ManagedDatabases []ManagedDatabaseGroupManagedDatabase `pulumi:"managedDatabases"`
	// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a ManagedDatabaseGroup resource.
type ManagedDatabaseGroupArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The information specified by the user about the Managed Database Group.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
	ManagedDatabases ManagedDatabaseGroupManagedDatabaseArrayInput
	// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
	Name pulumi.StringPtrInput
}

func (ManagedDatabaseGroupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*managedDatabaseGroupArgs)(nil)).Elem()
}

type ManagedDatabaseGroupInput interface {
	pulumi.Input

	ToManagedDatabaseGroupOutput() ManagedDatabaseGroupOutput
	ToManagedDatabaseGroupOutputWithContext(ctx context.Context) ManagedDatabaseGroupOutput
}

func (*ManagedDatabaseGroup) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedDatabaseGroup)(nil)).Elem()
}

func (i *ManagedDatabaseGroup) ToManagedDatabaseGroupOutput() ManagedDatabaseGroupOutput {
	return i.ToManagedDatabaseGroupOutputWithContext(context.Background())
}

func (i *ManagedDatabaseGroup) ToManagedDatabaseGroupOutputWithContext(ctx context.Context) ManagedDatabaseGroupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabaseGroupOutput)
}

// ManagedDatabaseGroupArrayInput is an input type that accepts ManagedDatabaseGroupArray and ManagedDatabaseGroupArrayOutput values.
// You can construct a concrete instance of `ManagedDatabaseGroupArrayInput` via:
//
//	ManagedDatabaseGroupArray{ ManagedDatabaseGroupArgs{...} }
type ManagedDatabaseGroupArrayInput interface {
	pulumi.Input

	ToManagedDatabaseGroupArrayOutput() ManagedDatabaseGroupArrayOutput
	ToManagedDatabaseGroupArrayOutputWithContext(context.Context) ManagedDatabaseGroupArrayOutput
}

type ManagedDatabaseGroupArray []ManagedDatabaseGroupInput

func (ManagedDatabaseGroupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedDatabaseGroup)(nil)).Elem()
}

func (i ManagedDatabaseGroupArray) ToManagedDatabaseGroupArrayOutput() ManagedDatabaseGroupArrayOutput {
	return i.ToManagedDatabaseGroupArrayOutputWithContext(context.Background())
}

func (i ManagedDatabaseGroupArray) ToManagedDatabaseGroupArrayOutputWithContext(ctx context.Context) ManagedDatabaseGroupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabaseGroupArrayOutput)
}

// ManagedDatabaseGroupMapInput is an input type that accepts ManagedDatabaseGroupMap and ManagedDatabaseGroupMapOutput values.
// You can construct a concrete instance of `ManagedDatabaseGroupMapInput` via:
//
//	ManagedDatabaseGroupMap{ "key": ManagedDatabaseGroupArgs{...} }
type ManagedDatabaseGroupMapInput interface {
	pulumi.Input

	ToManagedDatabaseGroupMapOutput() ManagedDatabaseGroupMapOutput
	ToManagedDatabaseGroupMapOutputWithContext(context.Context) ManagedDatabaseGroupMapOutput
}

type ManagedDatabaseGroupMap map[string]ManagedDatabaseGroupInput

func (ManagedDatabaseGroupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedDatabaseGroup)(nil)).Elem()
}

func (i ManagedDatabaseGroupMap) ToManagedDatabaseGroupMapOutput() ManagedDatabaseGroupMapOutput {
	return i.ToManagedDatabaseGroupMapOutputWithContext(context.Background())
}

func (i ManagedDatabaseGroupMap) ToManagedDatabaseGroupMapOutputWithContext(ctx context.Context) ManagedDatabaseGroupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabaseGroupMapOutput)
}

type ManagedDatabaseGroupOutput struct{ *pulumi.OutputState }

func (ManagedDatabaseGroupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedDatabaseGroup)(nil)).Elem()
}

func (o ManagedDatabaseGroupOutput) ToManagedDatabaseGroupOutput() ManagedDatabaseGroupOutput {
	return o
}

func (o ManagedDatabaseGroupOutput) ToManagedDatabaseGroupOutputWithContext(ctx context.Context) ManagedDatabaseGroupOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
func (o ManagedDatabaseGroupOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ManagedDatabaseGroupOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The information specified by the user about the Managed Database Group.
func (o ManagedDatabaseGroupOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ManagedDatabaseGroupOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
func (o ManagedDatabaseGroupOutput) ManagedDatabases() ManagedDatabaseGroupManagedDatabaseArrayOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) ManagedDatabaseGroupManagedDatabaseArrayOutput {
		return v.ManagedDatabases
	}).(ManagedDatabaseGroupManagedDatabaseArrayOutput)
}

// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
func (o ManagedDatabaseGroupOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The current lifecycle state of the Managed Database Group.
func (o ManagedDatabaseGroupOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ManagedDatabaseGroupOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the Managed Database Group was created.
func (o ManagedDatabaseGroupOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the Managed Database Group was last updated.
func (o ManagedDatabaseGroupOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabaseGroup) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type ManagedDatabaseGroupArrayOutput struct{ *pulumi.OutputState }

func (ManagedDatabaseGroupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedDatabaseGroup)(nil)).Elem()
}

func (o ManagedDatabaseGroupArrayOutput) ToManagedDatabaseGroupArrayOutput() ManagedDatabaseGroupArrayOutput {
	return o
}

func (o ManagedDatabaseGroupArrayOutput) ToManagedDatabaseGroupArrayOutputWithContext(ctx context.Context) ManagedDatabaseGroupArrayOutput {
	return o
}

func (o ManagedDatabaseGroupArrayOutput) Index(i pulumi.IntInput) ManagedDatabaseGroupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ManagedDatabaseGroup {
		return vs[0].([]*ManagedDatabaseGroup)[vs[1].(int)]
	}).(ManagedDatabaseGroupOutput)
}

type ManagedDatabaseGroupMapOutput struct{ *pulumi.OutputState }

func (ManagedDatabaseGroupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedDatabaseGroup)(nil)).Elem()
}

func (o ManagedDatabaseGroupMapOutput) ToManagedDatabaseGroupMapOutput() ManagedDatabaseGroupMapOutput {
	return o
}

func (o ManagedDatabaseGroupMapOutput) ToManagedDatabaseGroupMapOutputWithContext(ctx context.Context) ManagedDatabaseGroupMapOutput {
	return o
}

func (o ManagedDatabaseGroupMapOutput) MapIndex(k pulumi.StringInput) ManagedDatabaseGroupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ManagedDatabaseGroup {
		return vs[0].(map[string]*ManagedDatabaseGroup)[vs[1].(string)]
	}).(ManagedDatabaseGroupOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabaseGroupInput)(nil)).Elem(), &ManagedDatabaseGroup{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabaseGroupArrayInput)(nil)).Elem(), ManagedDatabaseGroupArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabaseGroupMapInput)(nil)).Elem(), ManagedDatabaseGroupMap{})
	pulumi.RegisterOutputType(ManagedDatabaseGroupOutput{})
	pulumi.RegisterOutputType(ManagedDatabaseGroupArrayOutput{})
	pulumi.RegisterOutputType(ManagedDatabaseGroupMapOutput{})
}
