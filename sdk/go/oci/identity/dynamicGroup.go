// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Dynamic Group resource in Oracle Cloud Infrastructure Identity service.
//
// Creates a new dynamic group in your tenancy.
//
// You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
// is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
// reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
// reside within compartments inside the tenancy. For information about OCIDs, see
// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// You must also specify a *name* for the dynamic group, which must be unique across all dynamic groups in your
// tenancy, and cannot be changed. Note that this name has to be also unique across all groups in your tenancy.
// You can use this name or the OCID when writing policies that apply to the dynamic group. For more information
// about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).
//
// You must also specify a *description* for the dynamic group (although it can be an empty string). It does not
// have to be unique, and you can change it anytime with [UpdateDynamicGroup](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/DynamicGroup/UpdateDynamicGroup).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.NewDynamicGroup(ctx, "test_dynamic_group", &identity.DynamicGroupArgs{
//				CompartmentId: pulumi.Any(tenancyOcid),
//				Description:   pulumi.Any(dynamicGroupDescription),
//				MatchingRule:  pulumi.Any(dynamicGroupMatchingRule),
//				Name:          pulumi.Any(dynamicGroupName),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
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
// DynamicGroups can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Identity/dynamicGroup:DynamicGroup test_dynamic_group "id"
// ```
type DynamicGroup struct {
	pulumi.CustomResourceState

	// The OCID of the tenancy containing the group.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringOutput `pulumi:"inactiveState"`
	// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
	MatchingRule pulumi.StringOutput `pulumi:"matchingRule"`
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringOutput `pulumi:"name"`
	// The group's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewDynamicGroup registers a new resource with the given unique name, arguments, and options.
func NewDynamicGroup(ctx *pulumi.Context,
	name string, args *DynamicGroupArgs, opts ...pulumi.ResourceOption) (*DynamicGroup, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.Description == nil {
		return nil, errors.New("invalid value for required argument 'Description'")
	}
	if args.MatchingRule == nil {
		return nil, errors.New("invalid value for required argument 'MatchingRule'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DynamicGroup
	err := ctx.RegisterResource("oci:Identity/dynamicGroup:DynamicGroup", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDynamicGroup gets an existing DynamicGroup resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDynamicGroup(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DynamicGroupState, opts ...pulumi.ResourceOption) (*DynamicGroup, error) {
	var resource DynamicGroup
	err := ctx.ReadResource("oci:Identity/dynamicGroup:DynamicGroup", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DynamicGroup resources.
type dynamicGroupState struct {
	// The OCID of the tenancy containing the group.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The detailed status of INACTIVE lifecycleState.
	InactiveState *string `pulumi:"inactiveState"`
	// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
	MatchingRule *string `pulumi:"matchingRule"`
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name *string `pulumi:"name"`
	// The group's current state.
	State *string `pulumi:"state"`
	// Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type DynamicGroupState struct {
	// The OCID of the tenancy containing the group.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The detailed status of INACTIVE lifecycleState.
	InactiveState pulumi.StringPtrInput
	// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
	MatchingRule pulumi.StringPtrInput
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringPtrInput
	// The group's current state.
	State pulumi.StringPtrInput
	// Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (DynamicGroupState) ElementType() reflect.Type {
	return reflect.TypeOf((*dynamicGroupState)(nil)).Elem()
}

type dynamicGroupArgs struct {
	// The OCID of the tenancy containing the group.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
	Description string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
	MatchingRule string `pulumi:"matchingRule"`
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a DynamicGroup resource.
type DynamicGroupArgs struct {
	// The OCID of the tenancy containing the group.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
	Description pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
	MatchingRule pulumi.StringInput
	// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringPtrInput
}

func (DynamicGroupArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dynamicGroupArgs)(nil)).Elem()
}

type DynamicGroupInput interface {
	pulumi.Input

	ToDynamicGroupOutput() DynamicGroupOutput
	ToDynamicGroupOutputWithContext(ctx context.Context) DynamicGroupOutput
}

func (*DynamicGroup) ElementType() reflect.Type {
	return reflect.TypeOf((**DynamicGroup)(nil)).Elem()
}

func (i *DynamicGroup) ToDynamicGroupOutput() DynamicGroupOutput {
	return i.ToDynamicGroupOutputWithContext(context.Background())
}

func (i *DynamicGroup) ToDynamicGroupOutputWithContext(ctx context.Context) DynamicGroupOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DynamicGroupOutput)
}

// DynamicGroupArrayInput is an input type that accepts DynamicGroupArray and DynamicGroupArrayOutput values.
// You can construct a concrete instance of `DynamicGroupArrayInput` via:
//
//	DynamicGroupArray{ DynamicGroupArgs{...} }
type DynamicGroupArrayInput interface {
	pulumi.Input

	ToDynamicGroupArrayOutput() DynamicGroupArrayOutput
	ToDynamicGroupArrayOutputWithContext(context.Context) DynamicGroupArrayOutput
}

type DynamicGroupArray []DynamicGroupInput

func (DynamicGroupArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DynamicGroup)(nil)).Elem()
}

func (i DynamicGroupArray) ToDynamicGroupArrayOutput() DynamicGroupArrayOutput {
	return i.ToDynamicGroupArrayOutputWithContext(context.Background())
}

func (i DynamicGroupArray) ToDynamicGroupArrayOutputWithContext(ctx context.Context) DynamicGroupArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DynamicGroupArrayOutput)
}

// DynamicGroupMapInput is an input type that accepts DynamicGroupMap and DynamicGroupMapOutput values.
// You can construct a concrete instance of `DynamicGroupMapInput` via:
//
//	DynamicGroupMap{ "key": DynamicGroupArgs{...} }
type DynamicGroupMapInput interface {
	pulumi.Input

	ToDynamicGroupMapOutput() DynamicGroupMapOutput
	ToDynamicGroupMapOutputWithContext(context.Context) DynamicGroupMapOutput
}

type DynamicGroupMap map[string]DynamicGroupInput

func (DynamicGroupMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DynamicGroup)(nil)).Elem()
}

func (i DynamicGroupMap) ToDynamicGroupMapOutput() DynamicGroupMapOutput {
	return i.ToDynamicGroupMapOutputWithContext(context.Background())
}

func (i DynamicGroupMap) ToDynamicGroupMapOutputWithContext(ctx context.Context) DynamicGroupMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DynamicGroupMapOutput)
}

type DynamicGroupOutput struct{ *pulumi.OutputState }

func (DynamicGroupOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DynamicGroup)(nil)).Elem()
}

func (o DynamicGroupOutput) ToDynamicGroupOutput() DynamicGroupOutput {
	return o
}

func (o DynamicGroupOutput) ToDynamicGroupOutputWithContext(ctx context.Context) DynamicGroupOutput {
	return o
}

// The OCID of the tenancy containing the group.
func (o DynamicGroupOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o DynamicGroupOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
func (o DynamicGroupOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o DynamicGroupOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The detailed status of INACTIVE lifecycleState.
func (o DynamicGroupOutput) InactiveState() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.InactiveState }).(pulumi.StringOutput)
}

// (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
func (o DynamicGroupOutput) MatchingRule() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.MatchingRule }).(pulumi.StringOutput)
}

// The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DynamicGroupOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The group's current state.
func (o DynamicGroupOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
func (o DynamicGroupOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DynamicGroup) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type DynamicGroupArrayOutput struct{ *pulumi.OutputState }

func (DynamicGroupArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DynamicGroup)(nil)).Elem()
}

func (o DynamicGroupArrayOutput) ToDynamicGroupArrayOutput() DynamicGroupArrayOutput {
	return o
}

func (o DynamicGroupArrayOutput) ToDynamicGroupArrayOutputWithContext(ctx context.Context) DynamicGroupArrayOutput {
	return o
}

func (o DynamicGroupArrayOutput) Index(i pulumi.IntInput) DynamicGroupOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DynamicGroup {
		return vs[0].([]*DynamicGroup)[vs[1].(int)]
	}).(DynamicGroupOutput)
}

type DynamicGroupMapOutput struct{ *pulumi.OutputState }

func (DynamicGroupMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DynamicGroup)(nil)).Elem()
}

func (o DynamicGroupMapOutput) ToDynamicGroupMapOutput() DynamicGroupMapOutput {
	return o
}

func (o DynamicGroupMapOutput) ToDynamicGroupMapOutputWithContext(ctx context.Context) DynamicGroupMapOutput {
	return o
}

func (o DynamicGroupMapOutput) MapIndex(k pulumi.StringInput) DynamicGroupOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DynamicGroup {
		return vs[0].(map[string]*DynamicGroup)[vs[1].(string)]
	}).(DynamicGroupOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DynamicGroupInput)(nil)).Elem(), &DynamicGroup{})
	pulumi.RegisterInputType(reflect.TypeOf((*DynamicGroupArrayInput)(nil)).Elem(), DynamicGroupArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DynamicGroupMapInput)(nil)).Elem(), DynamicGroupMap{})
	pulumi.RegisterOutputType(DynamicGroupOutput{})
	pulumi.RegisterOutputType(DynamicGroupArrayOutput{})
	pulumi.RegisterOutputType(DynamicGroupMapOutput{})
}
