// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Library Masking Format resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified library masking format.
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
//			_, err := DataSafe.GetLibraryMaskingFormat(ctx, &datasafe.GetLibraryMaskingFormatArgs{
//				LibraryMaskingFormatId: oci_data_safe_library_masking_format.Test_library_masking_format.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetLibraryMaskingFormat(ctx *pulumi.Context, args *GetLibraryMaskingFormatArgs, opts ...pulumi.InvokeOption) (*GetLibraryMaskingFormatResult, error) {
	var rv GetLibraryMaskingFormatResult
	err := ctx.Invoke("oci:DataSafe/getLibraryMaskingFormat:getLibraryMaskingFormat", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getLibraryMaskingFormat.
type GetLibraryMaskingFormatArgs struct {
	// The OCID of the library masking format.
	LibraryMaskingFormatId string `pulumi:"libraryMaskingFormatId"`
}

// A collection of values returned by getLibraryMaskingFormat.
type GetLibraryMaskingFormatResult struct {
	// The OCID of the compartment that contains the library masking format.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The description of the format entry.
	Description string `pulumi:"description"`
	// The display name of the library masking format.
	DisplayName string `pulumi:"displayName"`
	// An array of format entries. The combined output of all the format entries is used for masking.
	FormatEntries []GetLibraryMaskingFormatFormatEntry `pulumi:"formatEntries"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the library masking format.
	Id string `pulumi:"id"`
	// The OCID of the library masking format.
	LibraryMaskingFormatId string `pulumi:"libraryMaskingFormatId"`
	// An array of OCIDs of the sensitive types compatible with the library masking format.
	SensitiveTypeIds []string `pulumi:"sensitiveTypeIds"`
	// Specifies whether the library masking format is user-defined or predefined.
	Source string `pulumi:"source"`
	// The current state of the library masking format.
	State string `pulumi:"state"`
	// The date and time the library masking format was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the library masking format was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
	TimeUpdated string `pulumi:"timeUpdated"`
}

func GetLibraryMaskingFormatOutput(ctx *pulumi.Context, args GetLibraryMaskingFormatOutputArgs, opts ...pulumi.InvokeOption) GetLibraryMaskingFormatResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetLibraryMaskingFormatResult, error) {
			args := v.(GetLibraryMaskingFormatArgs)
			r, err := GetLibraryMaskingFormat(ctx, &args, opts...)
			var s GetLibraryMaskingFormatResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetLibraryMaskingFormatResultOutput)
}

// A collection of arguments for invoking getLibraryMaskingFormat.
type GetLibraryMaskingFormatOutputArgs struct {
	// The OCID of the library masking format.
	LibraryMaskingFormatId pulumi.StringInput `pulumi:"libraryMaskingFormatId"`
}

func (GetLibraryMaskingFormatOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLibraryMaskingFormatArgs)(nil)).Elem()
}

// A collection of values returned by getLibraryMaskingFormat.
type GetLibraryMaskingFormatResultOutput struct{ *pulumi.OutputState }

func (GetLibraryMaskingFormatResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetLibraryMaskingFormatResult)(nil)).Elem()
}

func (o GetLibraryMaskingFormatResultOutput) ToGetLibraryMaskingFormatResultOutput() GetLibraryMaskingFormatResultOutput {
	return o
}

func (o GetLibraryMaskingFormatResultOutput) ToGetLibraryMaskingFormatResultOutputWithContext(ctx context.Context) GetLibraryMaskingFormatResultOutput {
	return o
}

// The OCID of the compartment that contains the library masking format.
func (o GetLibraryMaskingFormatResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o GetLibraryMaskingFormatResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The description of the format entry.
func (o GetLibraryMaskingFormatResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the library masking format.
func (o GetLibraryMaskingFormatResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// An array of format entries. The combined output of all the format entries is used for masking.
func (o GetLibraryMaskingFormatResultOutput) FormatEntries() GetLibraryMaskingFormatFormatEntryArrayOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) []GetLibraryMaskingFormatFormatEntry { return v.FormatEntries }).(GetLibraryMaskingFormatFormatEntryArrayOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o GetLibraryMaskingFormatResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the library masking format.
func (o GetLibraryMaskingFormatResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the library masking format.
func (o GetLibraryMaskingFormatResultOutput) LibraryMaskingFormatId() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.LibraryMaskingFormatId }).(pulumi.StringOutput)
}

// An array of OCIDs of the sensitive types compatible with the library masking format.
func (o GetLibraryMaskingFormatResultOutput) SensitiveTypeIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) []string { return v.SensitiveTypeIds }).(pulumi.StringArrayOutput)
}

// Specifies whether the library masking format is user-defined or predefined.
func (o GetLibraryMaskingFormatResultOutput) Source() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.Source }).(pulumi.StringOutput)
}

// The current state of the library masking format.
func (o GetLibraryMaskingFormatResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the library masking format was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
func (o GetLibraryMaskingFormatResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the library masking format was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
func (o GetLibraryMaskingFormatResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetLibraryMaskingFormatResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetLibraryMaskingFormatResultOutput{})
}