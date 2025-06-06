// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Data Mask Rule resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a new DataMaskRule resource definition.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.NewDataMaskRule(ctx, "test_data_mask_rule", &cloudguard.DataMaskRuleArgs{
//				CompartmentId:      pulumi.Any(compartmentId),
//				DataMaskCategories: pulumi.Any(dataMaskRuleDataMaskCategories),
//				DisplayName:        pulumi.Any(dataMaskRuleDisplayName),
//				IamGroupId:         pulumi.Any(testGroup.Id),
//				TargetSelected: &cloudguard.DataMaskRuleTargetSelectedArgs{
//					Kind:   pulumi.Any(dataMaskRuleTargetSelectedKind),
//					Values: pulumi.Any(dataMaskRuleTargetSelectedValues),
//				},
//				DataMaskRuleStatus: pulumi.Any(dataMaskRuleDataMaskRuleStatus),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(dataMaskRuleDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				State: pulumi.Any(dataMaskRuleState),
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
// DataMaskRules can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudGuard/dataMaskRule:DataMaskRule test_data_mask_rule "id"
// ```
type DataMaskRule struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment OCID where the resource is created
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Data mask rule categories
	DataMaskCategories pulumi.StringArrayOutput `pulumi:"dataMaskCategories"`
	// (Updatable) The current status of the data mask rule
	DataMaskRuleStatus pulumi.StringOutput `pulumi:"dataMaskRuleStatus"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// The data mask rule description Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Data mask rule display name
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) IAM group ID associated with the data mask rule
	IamGroupId pulumi.StringOutput `pulumi:"iamGroupId"`
	// Additional details on the substate of the lifecycle state [DEPRECATE]
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// The current lifecycle state of the data mask rule
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
	TargetSelected DataMaskRuleTargetSelectedOutput `pulumi:"targetSelected"`
	// The date and time the target was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the target was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDataMaskRule registers a new resource with the given unique name, arguments, and options.
func NewDataMaskRule(ctx *pulumi.Context,
	name string, args *DataMaskRuleArgs, opts ...pulumi.ResourceOption) (*DataMaskRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DataMaskCategories == nil {
		return nil, errors.New("invalid value for required argument 'DataMaskCategories'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.IamGroupId == nil {
		return nil, errors.New("invalid value for required argument 'IamGroupId'")
	}
	if args.TargetSelected == nil {
		return nil, errors.New("invalid value for required argument 'TargetSelected'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DataMaskRule
	err := ctx.RegisterResource("oci:CloudGuard/dataMaskRule:DataMaskRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDataMaskRule gets an existing DataMaskRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDataMaskRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DataMaskRuleState, opts ...pulumi.ResourceOption) (*DataMaskRule, error) {
	var resource DataMaskRule
	err := ctx.ReadResource("oci:CloudGuard/dataMaskRule:DataMaskRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DataMaskRule resources.
type dataMaskRuleState struct {
	// (Updatable) Compartment OCID where the resource is created
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Data mask rule categories
	DataMaskCategories []string `pulumi:"dataMaskCategories"`
	// (Updatable) The current status of the data mask rule
	DataMaskRuleStatus *string `pulumi:"dataMaskRuleStatus"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The data mask rule description Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Data mask rule display name
	//
	// Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) IAM group ID associated with the data mask rule
	IamGroupId *string `pulumi:"iamGroupId"`
	// Additional details on the substate of the lifecycle state [DEPRECATE]
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// The current lifecycle state of the data mask rule
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
	TargetSelected *DataMaskRuleTargetSelected `pulumi:"targetSelected"`
	// The date and time the target was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the target was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DataMaskRuleState struct {
	// (Updatable) Compartment OCID where the resource is created
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Data mask rule categories
	DataMaskCategories pulumi.StringArrayInput
	// (Updatable) The current status of the data mask rule
	DataMaskRuleStatus pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// The data mask rule description Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Data mask rule display name
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// (Updatable) IAM group ID associated with the data mask rule
	IamGroupId pulumi.StringPtrInput
	// Additional details on the substate of the lifecycle state [DEPRECATE]
	LifecyleDetails pulumi.StringPtrInput
	// The current lifecycle state of the data mask rule
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
	TargetSelected DataMaskRuleTargetSelectedPtrInput
	// The date and time the target was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the target was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (DataMaskRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*dataMaskRuleState)(nil)).Elem()
}

type dataMaskRuleArgs struct {
	// (Updatable) Compartment OCID where the resource is created
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Data mask rule categories
	DataMaskCategories []string `pulumi:"dataMaskCategories"`
	// (Updatable) The current status of the data mask rule
	DataMaskRuleStatus *string `pulumi:"dataMaskRuleStatus"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The data mask rule description Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Data mask rule display name
	//
	// Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) IAM group ID associated with the data mask rule
	IamGroupId string `pulumi:"iamGroupId"`
	// The current lifecycle state of the data mask rule
	State *string `pulumi:"state"`
	// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
	TargetSelected DataMaskRuleTargetSelected `pulumi:"targetSelected"`
}

// The set of arguments for constructing a DataMaskRule resource.
type DataMaskRuleArgs struct {
	// (Updatable) Compartment OCID where the resource is created
	CompartmentId pulumi.StringInput
	// (Updatable) Data mask rule categories
	DataMaskCategories pulumi.StringArrayInput
	// (Updatable) The current status of the data mask rule
	DataMaskRuleStatus pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// The data mask rule description Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Data mask rule display name
	//
	// Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// (Updatable) IAM group ID associated with the data mask rule
	IamGroupId pulumi.StringInput
	// The current lifecycle state of the data mask rule
	State pulumi.StringPtrInput
	// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
	TargetSelected DataMaskRuleTargetSelectedInput
}

func (DataMaskRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dataMaskRuleArgs)(nil)).Elem()
}

type DataMaskRuleInput interface {
	pulumi.Input

	ToDataMaskRuleOutput() DataMaskRuleOutput
	ToDataMaskRuleOutputWithContext(ctx context.Context) DataMaskRuleOutput
}

func (*DataMaskRule) ElementType() reflect.Type {
	return reflect.TypeOf((**DataMaskRule)(nil)).Elem()
}

func (i *DataMaskRule) ToDataMaskRuleOutput() DataMaskRuleOutput {
	return i.ToDataMaskRuleOutputWithContext(context.Background())
}

func (i *DataMaskRule) ToDataMaskRuleOutputWithContext(ctx context.Context) DataMaskRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataMaskRuleOutput)
}

// DataMaskRuleArrayInput is an input type that accepts DataMaskRuleArray and DataMaskRuleArrayOutput values.
// You can construct a concrete instance of `DataMaskRuleArrayInput` via:
//
//	DataMaskRuleArray{ DataMaskRuleArgs{...} }
type DataMaskRuleArrayInput interface {
	pulumi.Input

	ToDataMaskRuleArrayOutput() DataMaskRuleArrayOutput
	ToDataMaskRuleArrayOutputWithContext(context.Context) DataMaskRuleArrayOutput
}

type DataMaskRuleArray []DataMaskRuleInput

func (DataMaskRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataMaskRule)(nil)).Elem()
}

func (i DataMaskRuleArray) ToDataMaskRuleArrayOutput() DataMaskRuleArrayOutput {
	return i.ToDataMaskRuleArrayOutputWithContext(context.Background())
}

func (i DataMaskRuleArray) ToDataMaskRuleArrayOutputWithContext(ctx context.Context) DataMaskRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataMaskRuleArrayOutput)
}

// DataMaskRuleMapInput is an input type that accepts DataMaskRuleMap and DataMaskRuleMapOutput values.
// You can construct a concrete instance of `DataMaskRuleMapInput` via:
//
//	DataMaskRuleMap{ "key": DataMaskRuleArgs{...} }
type DataMaskRuleMapInput interface {
	pulumi.Input

	ToDataMaskRuleMapOutput() DataMaskRuleMapOutput
	ToDataMaskRuleMapOutputWithContext(context.Context) DataMaskRuleMapOutput
}

type DataMaskRuleMap map[string]DataMaskRuleInput

func (DataMaskRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataMaskRule)(nil)).Elem()
}

func (i DataMaskRuleMap) ToDataMaskRuleMapOutput() DataMaskRuleMapOutput {
	return i.ToDataMaskRuleMapOutputWithContext(context.Background())
}

func (i DataMaskRuleMap) ToDataMaskRuleMapOutputWithContext(ctx context.Context) DataMaskRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataMaskRuleMapOutput)
}

type DataMaskRuleOutput struct{ *pulumi.OutputState }

func (DataMaskRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DataMaskRule)(nil)).Elem()
}

func (o DataMaskRuleOutput) ToDataMaskRuleOutput() DataMaskRuleOutput {
	return o
}

func (o DataMaskRuleOutput) ToDataMaskRuleOutputWithContext(ctx context.Context) DataMaskRuleOutput {
	return o
}

// (Updatable) Compartment OCID where the resource is created
func (o DataMaskRuleOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Data mask rule categories
func (o DataMaskRuleOutput) DataMaskCategories() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringArrayOutput { return v.DataMaskCategories }).(pulumi.StringArrayOutput)
}

// (Updatable) The current status of the data mask rule
func (o DataMaskRuleOutput) DataMaskRuleStatus() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.DataMaskRuleStatus }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o DataMaskRuleOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The data mask rule description Avoid entering confidential information.
func (o DataMaskRuleOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Data mask rule display name
//
// Avoid entering confidential information.
func (o DataMaskRuleOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// Avoid entering confidential information.
func (o DataMaskRuleOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) IAM group ID associated with the data mask rule
func (o DataMaskRuleOutput) IamGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.IamGroupId }).(pulumi.StringOutput)
}

// Additional details on the substate of the lifecycle state [DEPRECATE]
func (o DataMaskRuleOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// The current lifecycle state of the data mask rule
func (o DataMaskRuleOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DataMaskRuleOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// (Updatable) Specification of how targets are to be selected (select ALL, or select by TargetResourceType or TargetId).
func (o DataMaskRuleOutput) TargetSelected() DataMaskRuleTargetSelectedOutput {
	return o.ApplyT(func(v *DataMaskRule) DataMaskRuleTargetSelectedOutput { return v.TargetSelected }).(DataMaskRuleTargetSelectedOutput)
}

// The date and time the target was created. Format defined by RFC3339.
func (o DataMaskRuleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the target was updated. Format defined by RFC3339.
func (o DataMaskRuleOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataMaskRule) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type DataMaskRuleArrayOutput struct{ *pulumi.OutputState }

func (DataMaskRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataMaskRule)(nil)).Elem()
}

func (o DataMaskRuleArrayOutput) ToDataMaskRuleArrayOutput() DataMaskRuleArrayOutput {
	return o
}

func (o DataMaskRuleArrayOutput) ToDataMaskRuleArrayOutputWithContext(ctx context.Context) DataMaskRuleArrayOutput {
	return o
}

func (o DataMaskRuleArrayOutput) Index(i pulumi.IntInput) DataMaskRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DataMaskRule {
		return vs[0].([]*DataMaskRule)[vs[1].(int)]
	}).(DataMaskRuleOutput)
}

type DataMaskRuleMapOutput struct{ *pulumi.OutputState }

func (DataMaskRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataMaskRule)(nil)).Elem()
}

func (o DataMaskRuleMapOutput) ToDataMaskRuleMapOutput() DataMaskRuleMapOutput {
	return o
}

func (o DataMaskRuleMapOutput) ToDataMaskRuleMapOutputWithContext(ctx context.Context) DataMaskRuleMapOutput {
	return o
}

func (o DataMaskRuleMapOutput) MapIndex(k pulumi.StringInput) DataMaskRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DataMaskRule {
		return vs[0].(map[string]*DataMaskRule)[vs[1].(string)]
	}).(DataMaskRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DataMaskRuleInput)(nil)).Elem(), &DataMaskRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataMaskRuleArrayInput)(nil)).Elem(), DataMaskRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataMaskRuleMapInput)(nil)).Elem(), DataMaskRuleMap{})
	pulumi.RegisterOutputType(DataMaskRuleOutput{})
	pulumi.RegisterOutputType(DataMaskRuleArrayOutput{})
	pulumi.RegisterOutputType(DataMaskRuleMapOutput{})
}
