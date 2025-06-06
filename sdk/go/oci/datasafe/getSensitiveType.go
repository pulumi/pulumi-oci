// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Sensitive Type resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified sensitive type.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetSensitiveType(ctx, &datasafe.GetSensitiveTypeArgs{
//				SensitiveTypeId: testSensitiveTypeOciDataSafeSensitiveType.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSensitiveType(ctx *pulumi.Context, args *LookupSensitiveTypeArgs, opts ...pulumi.InvokeOption) (*LookupSensitiveTypeResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSensitiveTypeResult
	err := ctx.Invoke("oci:DataSafe/getSensitiveType:getSensitiveType", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSensitiveType.
type LookupSensitiveTypeArgs struct {
	// The OCID of the sensitive type.
	SensitiveTypeId string `pulumi:"sensitiveTypeId"`
}

// A collection of values returned by getSensitiveType.
type LookupSensitiveTypeResult struct {
	// A regular expression to be used by data discovery for matching column comments.
	CommentPattern string `pulumi:"commentPattern"`
	// The OCID of the compartment that contains the sensitive type.
	CompartmentId string `pulumi:"compartmentId"`
	// A regular expression to be used by data discovery for matching column data values.
	DataPattern string `pulumi:"dataPattern"`
	// The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
	DefaultMaskingFormatId string `pulumi:"defaultMaskingFormatId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the sensitive type.
	Description string `pulumi:"description"`
	// The display name of the sensitive type.
	DisplayName string `pulumi:"displayName"`
	// The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
	EntityType string `pulumi:"entityType"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the sensitive type.
	Id string `pulumi:"id"`
	// Specifies whether the sensitive type is common. Common sensitive types belong to  library sensitive types which are frequently used to perform sensitive data discovery.
	IsCommon bool `pulumi:"isCommon"`
	// A regular expression to be used by data discovery for matching column names.
	NamePattern string `pulumi:"namePattern"`
	// The OCID of the parent sensitive category.
	ParentCategoryId string `pulumi:"parentCategoryId"`
	// The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
	SearchType      string `pulumi:"searchType"`
	SensitiveTypeId string `pulumi:"sensitiveTypeId"`
	// The short name of the sensitive type.
	ShortName string `pulumi:"shortName"`
	// Specifies whether the sensitive type is user-defined or predefined.
	Source string `pulumi:"source"`
	// The current state of the sensitive type.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupSensitiveTypeOutput(ctx *pulumi.Context, args LookupSensitiveTypeOutputArgs, opts ...pulumi.InvokeOption) LookupSensitiveTypeResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupSensitiveTypeResultOutput, error) {
			args := v.(LookupSensitiveTypeArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSensitiveType:getSensitiveType", args, LookupSensitiveTypeResultOutput{}, options).(LookupSensitiveTypeResultOutput), nil
		}).(LookupSensitiveTypeResultOutput)
}

// A collection of arguments for invoking getSensitiveType.
type LookupSensitiveTypeOutputArgs struct {
	// The OCID of the sensitive type.
	SensitiveTypeId pulumi.StringInput `pulumi:"sensitiveTypeId"`
}

func (LookupSensitiveTypeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSensitiveTypeArgs)(nil)).Elem()
}

// A collection of values returned by getSensitiveType.
type LookupSensitiveTypeResultOutput struct{ *pulumi.OutputState }

func (LookupSensitiveTypeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSensitiveTypeResult)(nil)).Elem()
}

func (o LookupSensitiveTypeResultOutput) ToLookupSensitiveTypeResultOutput() LookupSensitiveTypeResultOutput {
	return o
}

func (o LookupSensitiveTypeResultOutput) ToLookupSensitiveTypeResultOutputWithContext(ctx context.Context) LookupSensitiveTypeResultOutput {
	return o
}

// A regular expression to be used by data discovery for matching column comments.
func (o LookupSensitiveTypeResultOutput) CommentPattern() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.CommentPattern }).(pulumi.StringOutput)
}

// The OCID of the compartment that contains the sensitive type.
func (o LookupSensitiveTypeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A regular expression to be used by data discovery for matching column data values.
func (o LookupSensitiveTypeResultOutput) DataPattern() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.DataPattern }).(pulumi.StringOutput)
}

// The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
func (o LookupSensitiveTypeResultOutput) DefaultMaskingFormatId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.DefaultMaskingFormatId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o LookupSensitiveTypeResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the sensitive type.
func (o LookupSensitiveTypeResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the sensitive type.
func (o LookupSensitiveTypeResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
func (o LookupSensitiveTypeResultOutput) EntityType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.EntityType }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupSensitiveTypeResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the sensitive type.
func (o LookupSensitiveTypeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.Id }).(pulumi.StringOutput)
}

// Specifies whether the sensitive type is common. Common sensitive types belong to  library sensitive types which are frequently used to perform sensitive data discovery.
func (o LookupSensitiveTypeResultOutput) IsCommon() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) bool { return v.IsCommon }).(pulumi.BoolOutput)
}

// A regular expression to be used by data discovery for matching column names.
func (o LookupSensitiveTypeResultOutput) NamePattern() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.NamePattern }).(pulumi.StringOutput)
}

// The OCID of the parent sensitive category.
func (o LookupSensitiveTypeResultOutput) ParentCategoryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.ParentCategoryId }).(pulumi.StringOutput)
}

// The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
func (o LookupSensitiveTypeResultOutput) SearchType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.SearchType }).(pulumi.StringOutput)
}

func (o LookupSensitiveTypeResultOutput) SensitiveTypeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.SensitiveTypeId }).(pulumi.StringOutput)
}

// The short name of the sensitive type.
func (o LookupSensitiveTypeResultOutput) ShortName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.ShortName }).(pulumi.StringOutput)
}

// Specifies whether the sensitive type is user-defined or predefined.
func (o LookupSensitiveTypeResultOutput) Source() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.Source }).(pulumi.StringOutput)
}

// The current state of the sensitive type.
func (o LookupSensitiveTypeResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupSensitiveTypeResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupSensitiveTypeResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupSensitiveTypeResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveTypeResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSensitiveTypeResultOutput{})
}
