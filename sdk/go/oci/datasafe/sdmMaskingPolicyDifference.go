// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Sdm Masking Policy Difference resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates SDM masking policy difference for the specified masking policy. It finds the difference between
// masking columns of the masking policy and sensitive columns of the SDM. After performing this operation,
// you can use ListDifferenceColumns to view the difference columns, PatchSdmMaskingPolicyDifferenceColumns
// to specify the action you want perform on these columns, and then ApplySdmMaskingPolicyDifference to process the
// difference columns and apply them to the masking policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataSafe.NewSdmMaskingPolicyDifference(ctx, "testSdmMaskingPolicyDifference", &DataSafe.SdmMaskingPolicyDifferenceArgs{
//				CompartmentId:   pulumi.Any(_var.Compartment_id),
//				MaskingPolicyId: pulumi.Any(oci_data_safe_masking_policy.Test_masking_policy.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DifferenceType: pulumi.Any(_var.Sdm_masking_policy_difference_difference_type),
//				DisplayName:    pulumi.Any(_var.Sdm_masking_policy_difference_display_name),
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
// SdmMaskingPolicyDifferences can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference test_sdm_masking_policy_difference "id"
//
// ```
type SdmMaskingPolicyDifference struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DifferenceType pulumi.StringOutput `pulumi:"differenceType"`
	// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
	MaskingPolicyId pulumi.StringOutput `pulumi:"maskingPolicyId"`
	// The OCID of the sensitive data model associated with the SDM masking policy difference.
	SensitiveDataModelId pulumi.StringOutput `pulumi:"sensitiveDataModelId"`
	// The current state of the SDM masking policy difference.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreationStarted pulumi.StringOutput `pulumi:"timeCreationStarted"`
}

// NewSdmMaskingPolicyDifference registers a new resource with the given unique name, arguments, and options.
func NewSdmMaskingPolicyDifference(ctx *pulumi.Context,
	name string, args *SdmMaskingPolicyDifferenceArgs, opts ...pulumi.ResourceOption) (*SdmMaskingPolicyDifference, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.MaskingPolicyId == nil {
		return nil, errors.New("invalid value for required argument 'MaskingPolicyId'")
	}
	var resource SdmMaskingPolicyDifference
	err := ctx.RegisterResource("oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSdmMaskingPolicyDifference gets an existing SdmMaskingPolicyDifference resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSdmMaskingPolicyDifference(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SdmMaskingPolicyDifferenceState, opts ...pulumi.ResourceOption) (*SdmMaskingPolicyDifference, error) {
	var resource SdmMaskingPolicyDifference
	err := ctx.ReadResource("oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SdmMaskingPolicyDifference resources.
type sdmMaskingPolicyDifferenceState struct {
	// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DifferenceType *string `pulumi:"differenceType"`
	// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
	MaskingPolicyId *string `pulumi:"maskingPolicyId"`
	// The OCID of the sensitive data model associated with the SDM masking policy difference.
	SensitiveDataModelId *string `pulumi:"sensitiveDataModelId"`
	// The current state of the SDM masking policy difference.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreationStarted *string `pulumi:"timeCreationStarted"`
}

type SdmMaskingPolicyDifferenceState struct {
	// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DifferenceType pulumi.StringPtrInput
	// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
	MaskingPolicyId pulumi.StringPtrInput
	// The OCID of the sensitive data model associated with the SDM masking policy difference.
	SensitiveDataModelId pulumi.StringPtrInput
	// The current state of the SDM masking policy difference.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreationStarted pulumi.StringPtrInput
}

func (SdmMaskingPolicyDifferenceState) ElementType() reflect.Type {
	return reflect.TypeOf((*sdmMaskingPolicyDifferenceState)(nil)).Elem()
}

type sdmMaskingPolicyDifferenceArgs struct {
	// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DifferenceType *string `pulumi:"differenceType"`
	// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
	MaskingPolicyId string `pulumi:"maskingPolicyId"`
}

// The set of arguments for constructing a SdmMaskingPolicyDifference resource.
type SdmMaskingPolicyDifferenceArgs struct {
	// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DifferenceType pulumi.StringPtrInput
	// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
	MaskingPolicyId pulumi.StringInput
}

func (SdmMaskingPolicyDifferenceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*sdmMaskingPolicyDifferenceArgs)(nil)).Elem()
}

type SdmMaskingPolicyDifferenceInput interface {
	pulumi.Input

	ToSdmMaskingPolicyDifferenceOutput() SdmMaskingPolicyDifferenceOutput
	ToSdmMaskingPolicyDifferenceOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceOutput
}

func (*SdmMaskingPolicyDifference) ElementType() reflect.Type {
	return reflect.TypeOf((**SdmMaskingPolicyDifference)(nil)).Elem()
}

func (i *SdmMaskingPolicyDifference) ToSdmMaskingPolicyDifferenceOutput() SdmMaskingPolicyDifferenceOutput {
	return i.ToSdmMaskingPolicyDifferenceOutputWithContext(context.Background())
}

func (i *SdmMaskingPolicyDifference) ToSdmMaskingPolicyDifferenceOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SdmMaskingPolicyDifferenceOutput)
}

// SdmMaskingPolicyDifferenceArrayInput is an input type that accepts SdmMaskingPolicyDifferenceArray and SdmMaskingPolicyDifferenceArrayOutput values.
// You can construct a concrete instance of `SdmMaskingPolicyDifferenceArrayInput` via:
//
//	SdmMaskingPolicyDifferenceArray{ SdmMaskingPolicyDifferenceArgs{...} }
type SdmMaskingPolicyDifferenceArrayInput interface {
	pulumi.Input

	ToSdmMaskingPolicyDifferenceArrayOutput() SdmMaskingPolicyDifferenceArrayOutput
	ToSdmMaskingPolicyDifferenceArrayOutputWithContext(context.Context) SdmMaskingPolicyDifferenceArrayOutput
}

type SdmMaskingPolicyDifferenceArray []SdmMaskingPolicyDifferenceInput

func (SdmMaskingPolicyDifferenceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SdmMaskingPolicyDifference)(nil)).Elem()
}

func (i SdmMaskingPolicyDifferenceArray) ToSdmMaskingPolicyDifferenceArrayOutput() SdmMaskingPolicyDifferenceArrayOutput {
	return i.ToSdmMaskingPolicyDifferenceArrayOutputWithContext(context.Background())
}

func (i SdmMaskingPolicyDifferenceArray) ToSdmMaskingPolicyDifferenceArrayOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SdmMaskingPolicyDifferenceArrayOutput)
}

// SdmMaskingPolicyDifferenceMapInput is an input type that accepts SdmMaskingPolicyDifferenceMap and SdmMaskingPolicyDifferenceMapOutput values.
// You can construct a concrete instance of `SdmMaskingPolicyDifferenceMapInput` via:
//
//	SdmMaskingPolicyDifferenceMap{ "key": SdmMaskingPolicyDifferenceArgs{...} }
type SdmMaskingPolicyDifferenceMapInput interface {
	pulumi.Input

	ToSdmMaskingPolicyDifferenceMapOutput() SdmMaskingPolicyDifferenceMapOutput
	ToSdmMaskingPolicyDifferenceMapOutputWithContext(context.Context) SdmMaskingPolicyDifferenceMapOutput
}

type SdmMaskingPolicyDifferenceMap map[string]SdmMaskingPolicyDifferenceInput

func (SdmMaskingPolicyDifferenceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SdmMaskingPolicyDifference)(nil)).Elem()
}

func (i SdmMaskingPolicyDifferenceMap) ToSdmMaskingPolicyDifferenceMapOutput() SdmMaskingPolicyDifferenceMapOutput {
	return i.ToSdmMaskingPolicyDifferenceMapOutputWithContext(context.Background())
}

func (i SdmMaskingPolicyDifferenceMap) ToSdmMaskingPolicyDifferenceMapOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SdmMaskingPolicyDifferenceMapOutput)
}

type SdmMaskingPolicyDifferenceOutput struct{ *pulumi.OutputState }

func (SdmMaskingPolicyDifferenceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SdmMaskingPolicyDifference)(nil)).Elem()
}

func (o SdmMaskingPolicyDifferenceOutput) ToSdmMaskingPolicyDifferenceOutput() SdmMaskingPolicyDifferenceOutput {
	return o
}

func (o SdmMaskingPolicyDifferenceOutput) ToSdmMaskingPolicyDifferenceOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceOutput {
	return o
}

// (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
func (o SdmMaskingPolicyDifferenceOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o SdmMaskingPolicyDifferenceOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
func (o SdmMaskingPolicyDifferenceOutput) DifferenceType() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.DifferenceType }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
func (o SdmMaskingPolicyDifferenceOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o SdmMaskingPolicyDifferenceOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won't be allowed.
func (o SdmMaskingPolicyDifferenceOutput) MaskingPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.MaskingPolicyId }).(pulumi.StringOutput)
}

// The OCID of the sensitive data model associated with the SDM masking policy difference.
func (o SdmMaskingPolicyDifferenceOutput) SensitiveDataModelId() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.SensitiveDataModelId }).(pulumi.StringOutput)
}

// The current state of the SDM masking policy difference.
func (o SdmMaskingPolicyDifferenceOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o SdmMaskingPolicyDifferenceOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SdmMaskingPolicyDifferenceOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SdmMaskingPolicyDifferenceOutput) TimeCreationStarted() pulumi.StringOutput {
	return o.ApplyT(func(v *SdmMaskingPolicyDifference) pulumi.StringOutput { return v.TimeCreationStarted }).(pulumi.StringOutput)
}

type SdmMaskingPolicyDifferenceArrayOutput struct{ *pulumi.OutputState }

func (SdmMaskingPolicyDifferenceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SdmMaskingPolicyDifference)(nil)).Elem()
}

func (o SdmMaskingPolicyDifferenceArrayOutput) ToSdmMaskingPolicyDifferenceArrayOutput() SdmMaskingPolicyDifferenceArrayOutput {
	return o
}

func (o SdmMaskingPolicyDifferenceArrayOutput) ToSdmMaskingPolicyDifferenceArrayOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceArrayOutput {
	return o
}

func (o SdmMaskingPolicyDifferenceArrayOutput) Index(i pulumi.IntInput) SdmMaskingPolicyDifferenceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SdmMaskingPolicyDifference {
		return vs[0].([]*SdmMaskingPolicyDifference)[vs[1].(int)]
	}).(SdmMaskingPolicyDifferenceOutput)
}

type SdmMaskingPolicyDifferenceMapOutput struct{ *pulumi.OutputState }

func (SdmMaskingPolicyDifferenceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SdmMaskingPolicyDifference)(nil)).Elem()
}

func (o SdmMaskingPolicyDifferenceMapOutput) ToSdmMaskingPolicyDifferenceMapOutput() SdmMaskingPolicyDifferenceMapOutput {
	return o
}

func (o SdmMaskingPolicyDifferenceMapOutput) ToSdmMaskingPolicyDifferenceMapOutputWithContext(ctx context.Context) SdmMaskingPolicyDifferenceMapOutput {
	return o
}

func (o SdmMaskingPolicyDifferenceMapOutput) MapIndex(k pulumi.StringInput) SdmMaskingPolicyDifferenceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SdmMaskingPolicyDifference {
		return vs[0].(map[string]*SdmMaskingPolicyDifference)[vs[1].(string)]
	}).(SdmMaskingPolicyDifferenceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SdmMaskingPolicyDifferenceInput)(nil)).Elem(), &SdmMaskingPolicyDifference{})
	pulumi.RegisterInputType(reflect.TypeOf((*SdmMaskingPolicyDifferenceArrayInput)(nil)).Elem(), SdmMaskingPolicyDifferenceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SdmMaskingPolicyDifferenceMapInput)(nil)).Elem(), SdmMaskingPolicyDifferenceMap{})
	pulumi.RegisterOutputType(SdmMaskingPolicyDifferenceOutput{})
	pulumi.RegisterOutputType(SdmMaskingPolicyDifferenceArrayOutput{})
	pulumi.RegisterOutputType(SdmMaskingPolicyDifferenceMapOutput{})
}