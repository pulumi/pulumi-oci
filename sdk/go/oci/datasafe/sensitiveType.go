// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Sensitive Type resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a new sensitive type, which can be a basic sensitive type with regular expressions or a sensitive category.
// While sensitive types are used for data discovery, sensitive categories are used for logically grouping the related
// or similar sensitive types.
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
//			_, err := DataSafe.NewSensitiveType(ctx, "testSensitiveType", &DataSafe.SensitiveTypeArgs{
//				CompartmentId:          pulumi.Any(_var.Compartment_id),
//				EntityType:             pulumi.Any(_var.Sensitive_type_entity_type),
//				CommentPattern:         pulumi.Any(_var.Sensitive_type_comment_pattern),
//				DataPattern:            pulumi.Any(_var.Sensitive_type_data_pattern),
//				DefaultMaskingFormatId: pulumi.Any(oci_data_safe_default_masking_format.Test_default_masking_format.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				Description: pulumi.Any(_var.Sensitive_type_description),
//				DisplayName: pulumi.Any(_var.Sensitive_type_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				NamePattern:      pulumi.Any(_var.Sensitive_type_name_pattern),
//				ParentCategoryId: pulumi.Any(oci_marketplace_category.Test_category.Id),
//				SearchType:       pulumi.Any(_var.Sensitive_type_search_type),
//				ShortName:        pulumi.Any(_var.Sensitive_type_short_name),
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
// SensitiveTypes can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/sensitiveType:SensitiveType test_sensitive_type "id"
//
// ```
type SensitiveType struct {
	pulumi.CustomResourceState

	// (Updatable) A regular expression to be used by data discovery for matching column comments.
	CommentPattern pulumi.StringOutput `pulumi:"commentPattern"`
	// (Updatable) The OCID of the compartment where the sensitive type should be created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) A regular expression to be used by data discovery for matching column data values.
	DataPattern pulumi.StringOutput `pulumi:"dataPattern"`
	// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId pulumi.StringOutput `pulumi:"defaultMaskingFormatId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the sensitive type.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType pulumi.StringOutput `pulumi:"entityType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) A regular expression to be used by data discovery for matching column names.
	NamePattern pulumi.StringOutput `pulumi:"namePattern"`
	// (Updatable) The OCID of the parent sensitive category.
	ParentCategoryId pulumi.StringOutput `pulumi:"parentCategoryId"`
	// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType pulumi.StringOutput `pulumi:"searchType"`
	// (Updatable) The short name of the sensitive type.
	ShortName pulumi.StringOutput `pulumi:"shortName"`
	// Specifies whether the sensitive type is user-defined or predefined.
	Source pulumi.StringOutput `pulumi:"source"`
	// The current state of the sensitive type.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewSensitiveType registers a new resource with the given unique name, arguments, and options.
func NewSensitiveType(ctx *pulumi.Context,
	name string, args *SensitiveTypeArgs, opts ...pulumi.ResourceOption) (*SensitiveType, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.EntityType == nil {
		return nil, errors.New("invalid value for required argument 'EntityType'")
	}
	var resource SensitiveType
	err := ctx.RegisterResource("oci:DataSafe/sensitiveType:SensitiveType", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSensitiveType gets an existing SensitiveType resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSensitiveType(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SensitiveTypeState, opts ...pulumi.ResourceOption) (*SensitiveType, error) {
	var resource SensitiveType
	err := ctx.ReadResource("oci:DataSafe/sensitiveType:SensitiveType", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SensitiveType resources.
type sensitiveTypeState struct {
	// (Updatable) A regular expression to be used by data discovery for matching column comments.
	CommentPattern *string `pulumi:"commentPattern"`
	// (Updatable) The OCID of the compartment where the sensitive type should be created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) A regular expression to be used by data discovery for matching column data values.
	DataPattern *string `pulumi:"dataPattern"`
	// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId *string `pulumi:"defaultMaskingFormatId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the sensitive type.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType *string `pulumi:"entityType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) A regular expression to be used by data discovery for matching column names.
	NamePattern *string `pulumi:"namePattern"`
	// (Updatable) The OCID of the parent sensitive category.
	ParentCategoryId *string `pulumi:"parentCategoryId"`
	// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType *string `pulumi:"searchType"`
	// (Updatable) The short name of the sensitive type.
	ShortName *string `pulumi:"shortName"`
	// Specifies whether the sensitive type is user-defined or predefined.
	Source *string `pulumi:"source"`
	// The current state of the sensitive type.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type SensitiveTypeState struct {
	// (Updatable) A regular expression to be used by data discovery for matching column comments.
	CommentPattern pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment where the sensitive type should be created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) A regular expression to be used by data discovery for matching column data values.
	DataPattern pulumi.StringPtrInput
	// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the sensitive type.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) A regular expression to be used by data discovery for matching column names.
	NamePattern pulumi.StringPtrInput
	// (Updatable) The OCID of the parent sensitive category.
	ParentCategoryId pulumi.StringPtrInput
	// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType pulumi.StringPtrInput
	// (Updatable) The short name of the sensitive type.
	ShortName pulumi.StringPtrInput
	// Specifies whether the sensitive type is user-defined or predefined.
	Source pulumi.StringPtrInput
	// The current state of the sensitive type.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (SensitiveTypeState) ElementType() reflect.Type {
	return reflect.TypeOf((*sensitiveTypeState)(nil)).Elem()
}

type sensitiveTypeArgs struct {
	// (Updatable) A regular expression to be used by data discovery for matching column comments.
	CommentPattern *string `pulumi:"commentPattern"`
	// (Updatable) The OCID of the compartment where the sensitive type should be created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) A regular expression to be used by data discovery for matching column data values.
	DataPattern *string `pulumi:"dataPattern"`
	// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId *string `pulumi:"defaultMaskingFormatId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the sensitive type.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType string `pulumi:"entityType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) A regular expression to be used by data discovery for matching column names.
	NamePattern *string `pulumi:"namePattern"`
	// (Updatable) The OCID of the parent sensitive category.
	ParentCategoryId *string `pulumi:"parentCategoryId"`
	// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType *string `pulumi:"searchType"`
	// (Updatable) The short name of the sensitive type.
	ShortName *string `pulumi:"shortName"`
}

// The set of arguments for constructing a SensitiveType resource.
type SensitiveTypeArgs struct {
	// (Updatable) A regular expression to be used by data discovery for matching column comments.
	CommentPattern pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment where the sensitive type should be created.
	CompartmentId pulumi.StringInput
	// (Updatable) A regular expression to be used by data discovery for matching column data values.
	DataPattern pulumi.StringPtrInput
	// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the sensitive type.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) A regular expression to be used by data discovery for matching column names.
	NamePattern pulumi.StringPtrInput
	// (Updatable) The OCID of the parent sensitive category.
	ParentCategoryId pulumi.StringPtrInput
	// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType pulumi.StringPtrInput
	// (Updatable) The short name of the sensitive type.
	ShortName pulumi.StringPtrInput
}

func (SensitiveTypeArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*sensitiveTypeArgs)(nil)).Elem()
}

type SensitiveTypeInput interface {
	pulumi.Input

	ToSensitiveTypeOutput() SensitiveTypeOutput
	ToSensitiveTypeOutputWithContext(ctx context.Context) SensitiveTypeOutput
}

func (*SensitiveType) ElementType() reflect.Type {
	return reflect.TypeOf((**SensitiveType)(nil)).Elem()
}

func (i *SensitiveType) ToSensitiveTypeOutput() SensitiveTypeOutput {
	return i.ToSensitiveTypeOutputWithContext(context.Background())
}

func (i *SensitiveType) ToSensitiveTypeOutputWithContext(ctx context.Context) SensitiveTypeOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveTypeOutput)
}

// SensitiveTypeArrayInput is an input type that accepts SensitiveTypeArray and SensitiveTypeArrayOutput values.
// You can construct a concrete instance of `SensitiveTypeArrayInput` via:
//
//	SensitiveTypeArray{ SensitiveTypeArgs{...} }
type SensitiveTypeArrayInput interface {
	pulumi.Input

	ToSensitiveTypeArrayOutput() SensitiveTypeArrayOutput
	ToSensitiveTypeArrayOutputWithContext(context.Context) SensitiveTypeArrayOutput
}

type SensitiveTypeArray []SensitiveTypeInput

func (SensitiveTypeArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SensitiveType)(nil)).Elem()
}

func (i SensitiveTypeArray) ToSensitiveTypeArrayOutput() SensitiveTypeArrayOutput {
	return i.ToSensitiveTypeArrayOutputWithContext(context.Background())
}

func (i SensitiveTypeArray) ToSensitiveTypeArrayOutputWithContext(ctx context.Context) SensitiveTypeArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveTypeArrayOutput)
}

// SensitiveTypeMapInput is an input type that accepts SensitiveTypeMap and SensitiveTypeMapOutput values.
// You can construct a concrete instance of `SensitiveTypeMapInput` via:
//
//	SensitiveTypeMap{ "key": SensitiveTypeArgs{...} }
type SensitiveTypeMapInput interface {
	pulumi.Input

	ToSensitiveTypeMapOutput() SensitiveTypeMapOutput
	ToSensitiveTypeMapOutputWithContext(context.Context) SensitiveTypeMapOutput
}

type SensitiveTypeMap map[string]SensitiveTypeInput

func (SensitiveTypeMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SensitiveType)(nil)).Elem()
}

func (i SensitiveTypeMap) ToSensitiveTypeMapOutput() SensitiveTypeMapOutput {
	return i.ToSensitiveTypeMapOutputWithContext(context.Background())
}

func (i SensitiveTypeMap) ToSensitiveTypeMapOutputWithContext(ctx context.Context) SensitiveTypeMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SensitiveTypeMapOutput)
}

type SensitiveTypeOutput struct{ *pulumi.OutputState }

func (SensitiveTypeOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SensitiveType)(nil)).Elem()
}

func (o SensitiveTypeOutput) ToSensitiveTypeOutput() SensitiveTypeOutput {
	return o
}

func (o SensitiveTypeOutput) ToSensitiveTypeOutputWithContext(ctx context.Context) SensitiveTypeOutput {
	return o
}

// (Updatable) A regular expression to be used by data discovery for matching column comments.
func (o SensitiveTypeOutput) CommentPattern() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.CommentPattern }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment where the sensitive type should be created.
func (o SensitiveTypeOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) A regular expression to be used by data discovery for matching column data values.
func (o SensitiveTypeOutput) DataPattern() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.DataPattern }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
func (o SensitiveTypeOutput) DefaultMaskingFormatId() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.DefaultMaskingFormatId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o SensitiveTypeOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) The description of the sensitive type.
func (o SensitiveTypeOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the sensitive type. The name does not have to be unique, and it's changeable.
func (o SensitiveTypeOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
func (o SensitiveTypeOutput) EntityType() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.EntityType }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o SensitiveTypeOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) A regular expression to be used by data discovery for matching column names.
func (o SensitiveTypeOutput) NamePattern() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.NamePattern }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the parent sensitive category.
func (o SensitiveTypeOutput) ParentCategoryId() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.ParentCategoryId }).(pulumi.StringOutput)
}

// (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
func (o SensitiveTypeOutput) SearchType() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.SearchType }).(pulumi.StringOutput)
}

// (Updatable) The short name of the sensitive type.
func (o SensitiveTypeOutput) ShortName() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.ShortName }).(pulumi.StringOutput)
}

// Specifies whether the sensitive type is user-defined or predefined.
func (o SensitiveTypeOutput) Source() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.Source }).(pulumi.StringOutput)
}

// The current state of the sensitive type.
func (o SensitiveTypeOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o SensitiveTypeOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SensitiveTypeOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SensitiveTypeOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *SensitiveType) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type SensitiveTypeArrayOutput struct{ *pulumi.OutputState }

func (SensitiveTypeArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SensitiveType)(nil)).Elem()
}

func (o SensitiveTypeArrayOutput) ToSensitiveTypeArrayOutput() SensitiveTypeArrayOutput {
	return o
}

func (o SensitiveTypeArrayOutput) ToSensitiveTypeArrayOutputWithContext(ctx context.Context) SensitiveTypeArrayOutput {
	return o
}

func (o SensitiveTypeArrayOutput) Index(i pulumi.IntInput) SensitiveTypeOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SensitiveType {
		return vs[0].([]*SensitiveType)[vs[1].(int)]
	}).(SensitiveTypeOutput)
}

type SensitiveTypeMapOutput struct{ *pulumi.OutputState }

func (SensitiveTypeMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SensitiveType)(nil)).Elem()
}

func (o SensitiveTypeMapOutput) ToSensitiveTypeMapOutput() SensitiveTypeMapOutput {
	return o
}

func (o SensitiveTypeMapOutput) ToSensitiveTypeMapOutputWithContext(ctx context.Context) SensitiveTypeMapOutput {
	return o
}

func (o SensitiveTypeMapOutput) MapIndex(k pulumi.StringInput) SensitiveTypeOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SensitiveType {
		return vs[0].(map[string]*SensitiveType)[vs[1].(string)]
	}).(SensitiveTypeOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveTypeInput)(nil)).Elem(), &SensitiveType{})
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveTypeArrayInput)(nil)).Elem(), SensitiveTypeArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SensitiveTypeMapInput)(nil)).Elem(), SensitiveTypeMap{})
	pulumi.RegisterOutputType(SensitiveTypeOutput{})
	pulumi.RegisterOutputType(SensitiveTypeArrayOutput{})
	pulumi.RegisterOutputType(SensitiveTypeMapOutput{})
}