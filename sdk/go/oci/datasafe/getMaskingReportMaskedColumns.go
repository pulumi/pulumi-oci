// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Masking Reports Masked Columns in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of masked columns present in the specified masking report and based on the specified query parameters.
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
//			_, err := DataSafe.GetMaskingReportMaskedColumns(ctx, &datasafe.GetMaskingReportMaskedColumnsArgs{
//				MaskingReportId:     oci_data_safe_masking_report.Test_masking_report.Id,
//				ColumnNames:         _var.Masking_reports_masked_column_column_name,
//				MaskingColumnGroups: _var.Masking_reports_masked_column_masking_column_group,
//				Objects:             _var.Masking_reports_masked_column_object,
//				ObjectTypes:         _var.Masking_reports_masked_column_object_type,
//				SchemaNames:         _var.Masking_reports_masked_column_schema_name,
//				SensitiveTypeId:     pulumi.StringRef(oci_data_safe_sensitive_type.Test_sensitive_type.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMaskingReportMaskedColumns(ctx *pulumi.Context, args *GetMaskingReportMaskedColumnsArgs, opts ...pulumi.InvokeOption) (*GetMaskingReportMaskedColumnsResult, error) {
	var rv GetMaskingReportMaskedColumnsResult
	err := ctx.Invoke("oci:DataSafe/getMaskingReportMaskedColumns:getMaskingReportMaskedColumns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMaskingReportMaskedColumns.
type GetMaskingReportMaskedColumnsArgs struct {
	// A filter to return only a specific column based on column name.
	ColumnNames []string                              `pulumi:"columnNames"`
	Filters     []GetMaskingReportMaskedColumnsFilter `pulumi:"filters"`
	// A filter to return only the resources that match the specified masking column group.
	MaskingColumnGroups []string `pulumi:"maskingColumnGroups"`
	// The OCID of the masking report.
	MaskingReportId string `pulumi:"maskingReportId"`
	// A filter to return only items related to a specific object type.
	ObjectTypes []string `pulumi:"objectTypes"`
	// A filter to return only items related to a specific object name.
	Objects []string `pulumi:"objects"`
	// A filter to return only items related to specific schema name.
	SchemaNames []string `pulumi:"schemaNames"`
	// A filter to return only items related to a specific sensitive type OCID.
	SensitiveTypeId *string `pulumi:"sensitiveTypeId"`
}

// A collection of values returned by getMaskingReportMaskedColumns.
type GetMaskingReportMaskedColumnsResult struct {
	// The name of the masked column.
	ColumnNames []string                              `pulumi:"columnNames"`
	Filters     []GetMaskingReportMaskedColumnsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of masked_column_collection.
	MaskedColumnCollections []GetMaskingReportMaskedColumnsMaskedColumnCollection `pulumi:"maskedColumnCollections"`
	// The masking group of the masked column.
	MaskingColumnGroups []string `pulumi:"maskingColumnGroups"`
	MaskingReportId     string   `pulumi:"maskingReportId"`
	// The type of the object (table or editioning view) that contains the masked column.
	ObjectTypes []string `pulumi:"objectTypes"`
	// The name of the object (table or editioning view) that contains the masked column.
	Objects []string `pulumi:"objects"`
	// The name of the schema that contains the masked column.
	SchemaNames []string `pulumi:"schemaNames"`
	// The OCID of the sensitive type associated with the masked column.
	SensitiveTypeId *string `pulumi:"sensitiveTypeId"`
}

func GetMaskingReportMaskedColumnsOutput(ctx *pulumi.Context, args GetMaskingReportMaskedColumnsOutputArgs, opts ...pulumi.InvokeOption) GetMaskingReportMaskedColumnsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMaskingReportMaskedColumnsResult, error) {
			args := v.(GetMaskingReportMaskedColumnsArgs)
			r, err := GetMaskingReportMaskedColumns(ctx, &args, opts...)
			var s GetMaskingReportMaskedColumnsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMaskingReportMaskedColumnsResultOutput)
}

// A collection of arguments for invoking getMaskingReportMaskedColumns.
type GetMaskingReportMaskedColumnsOutputArgs struct {
	// A filter to return only a specific column based on column name.
	ColumnNames pulumi.StringArrayInput                       `pulumi:"columnNames"`
	Filters     GetMaskingReportMaskedColumnsFilterArrayInput `pulumi:"filters"`
	// A filter to return only the resources that match the specified masking column group.
	MaskingColumnGroups pulumi.StringArrayInput `pulumi:"maskingColumnGroups"`
	// The OCID of the masking report.
	MaskingReportId pulumi.StringInput `pulumi:"maskingReportId"`
	// A filter to return only items related to a specific object type.
	ObjectTypes pulumi.StringArrayInput `pulumi:"objectTypes"`
	// A filter to return only items related to a specific object name.
	Objects pulumi.StringArrayInput `pulumi:"objects"`
	// A filter to return only items related to specific schema name.
	SchemaNames pulumi.StringArrayInput `pulumi:"schemaNames"`
	// A filter to return only items related to a specific sensitive type OCID.
	SensitiveTypeId pulumi.StringPtrInput `pulumi:"sensitiveTypeId"`
}

func (GetMaskingReportMaskedColumnsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingReportMaskedColumnsArgs)(nil)).Elem()
}

// A collection of values returned by getMaskingReportMaskedColumns.
type GetMaskingReportMaskedColumnsResultOutput struct{ *pulumi.OutputState }

func (GetMaskingReportMaskedColumnsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingReportMaskedColumnsResult)(nil)).Elem()
}

func (o GetMaskingReportMaskedColumnsResultOutput) ToGetMaskingReportMaskedColumnsResultOutput() GetMaskingReportMaskedColumnsResultOutput {
	return o
}

func (o GetMaskingReportMaskedColumnsResultOutput) ToGetMaskingReportMaskedColumnsResultOutputWithContext(ctx context.Context) GetMaskingReportMaskedColumnsResultOutput {
	return o
}

// The name of the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) ColumnNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []string { return v.ColumnNames }).(pulumi.StringArrayOutput)
}

func (o GetMaskingReportMaskedColumnsResultOutput) Filters() GetMaskingReportMaskedColumnsFilterArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []GetMaskingReportMaskedColumnsFilter { return v.Filters }).(GetMaskingReportMaskedColumnsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMaskingReportMaskedColumnsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of masked_column_collection.
func (o GetMaskingReportMaskedColumnsResultOutput) MaskedColumnCollections() GetMaskingReportMaskedColumnsMaskedColumnCollectionArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []GetMaskingReportMaskedColumnsMaskedColumnCollection {
		return v.MaskedColumnCollections
	}).(GetMaskingReportMaskedColumnsMaskedColumnCollectionArrayOutput)
}

// The masking group of the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) MaskingColumnGroups() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []string { return v.MaskingColumnGroups }).(pulumi.StringArrayOutput)
}

func (o GetMaskingReportMaskedColumnsResultOutput) MaskingReportId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) string { return v.MaskingReportId }).(pulumi.StringOutput)
}

// The type of the object (table or editioning view) that contains the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) ObjectTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []string { return v.ObjectTypes }).(pulumi.StringArrayOutput)
}

// The name of the object (table or editioning view) that contains the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) Objects() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []string { return v.Objects }).(pulumi.StringArrayOutput)
}

// The name of the schema that contains the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) SchemaNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) []string { return v.SchemaNames }).(pulumi.StringArrayOutput)
}

// The OCID of the sensitive type associated with the masked column.
func (o GetMaskingReportMaskedColumnsResultOutput) SensitiveTypeId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMaskingReportMaskedColumnsResult) *string { return v.SensitiveTypeId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMaskingReportMaskedColumnsResultOutput{})
}