// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Sensitive Data Models Sensitive Column resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified sensitive column.
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
//			_, err := DataSafe.GetSensitiveDataModelsSensitiveColumn(ctx, &datasafe.GetSensitiveDataModelsSensitiveColumnArgs{
//				SensitiveColumnKey:   _var.Sensitive_data_models_sensitive_column_sensitive_column_key,
//				SensitiveDataModelId: oci_data_safe_sensitive_data_model.Test_sensitive_data_model.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSensitiveDataModelsSensitiveColumn(ctx *pulumi.Context, args *LookupSensitiveDataModelsSensitiveColumnArgs, opts ...pulumi.InvokeOption) (*LookupSensitiveDataModelsSensitiveColumnResult, error) {
	var rv LookupSensitiveDataModelsSensitiveColumnResult
	err := ctx.Invoke("oci:DataSafe/getSensitiveDataModelsSensitiveColumn:getSensitiveDataModelsSensitiveColumn", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSensitiveDataModelsSensitiveColumn.
type LookupSensitiveDataModelsSensitiveColumnArgs struct {
	// The unique key that identifies the sensitive column. It's numeric and unique within a sensitive data model.
	SensitiveColumnKey string `pulumi:"sensitiveColumnKey"`
	// The OCID of the sensitive data model.
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
}

// A collection of values returned by getSensitiveDataModelsSensitiveColumn.
type LookupSensitiveDataModelsSensitiveColumnResult struct {
	// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
	AppDefinedChildColumnKeys []string `pulumi:"appDefinedChildColumnKeys"`
	// The name of the application associated with the sensitive column. It's useful when the application name is different from the schema name. Otherwise, it can be ignored.
	AppName string `pulumi:"appName"`
	// The composite key groups to which the sensitive column belongs. If the column is part of a composite key, it's assigned a column group. It helps identify and manage referential relationships that involve composite keys.
	ColumnGroups []string `pulumi:"columnGroups"`
	// The name of the sensitive column.
	ColumnName string `pulumi:"columnName"`
	// The data type of the sensitive column.
	DataType string `pulumi:"dataType"`
	// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
	DbDefinedChildColumnKeys []string `pulumi:"dbDefinedChildColumnKeys"`
	// The estimated number of data values the column has in the associated database.
	EstimatedDataValueCount string `pulumi:"estimatedDataValueCount"`
	Id                      string `pulumi:"id"`
	// The unique key that identifies the sensitive column. It's numeric and unique within a sensitive data model.
	Key string `pulumi:"key"`
	// Details about the current state of the sensitive column.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The database object that contains the sensitive column.
	Object string `pulumi:"object"`
	// The type of the database object that contains the sensitive column.
	ObjectType string `pulumi:"objectType"`
	// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
	ParentColumnKeys []string `pulumi:"parentColumnKeys"`
	// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationType string `pulumi:"relationType"`
	// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
	SampleDataValues []string `pulumi:"sampleDataValues"`
	// The database schema that contains the sensitive column.
	SchemaName         string `pulumi:"schemaName"`
	SensitiveColumnKey string `pulumi:"sensitiveColumnKey"`
	// The OCID of the sensitive data model that contains the sensitive column.
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
	// The OCID of the sensitive type associated with the sensitive column.
	SensitiveTypeId string `pulumi:"sensitiveTypeId"`
	// The source of the sensitive column. DISCOVERY indicates that the column was added to the sensitive data model using a data discovery job. MANUAL indicates that the column was added manually.
	Source string `pulumi:"source"`
	// The current state of the sensitive column.
	State string `pulumi:"state"`
	// The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
	Status string `pulumi:"status"`
	// The date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339), the sensitive column was created in the sensitive data model.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339), the sensitive column was last updated in the sensitive data model.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupSensitiveDataModelsSensitiveColumnOutput(ctx *pulumi.Context, args LookupSensitiveDataModelsSensitiveColumnOutputArgs, opts ...pulumi.InvokeOption) LookupSensitiveDataModelsSensitiveColumnResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupSensitiveDataModelsSensitiveColumnResult, error) {
			args := v.(LookupSensitiveDataModelsSensitiveColumnArgs)
			r, err := LookupSensitiveDataModelsSensitiveColumn(ctx, &args, opts...)
			var s LookupSensitiveDataModelsSensitiveColumnResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupSensitiveDataModelsSensitiveColumnResultOutput)
}

// A collection of arguments for invoking getSensitiveDataModelsSensitiveColumn.
type LookupSensitiveDataModelsSensitiveColumnOutputArgs struct {
	// The unique key that identifies the sensitive column. It's numeric and unique within a sensitive data model.
	SensitiveColumnKey pulumi.StringInput `pulumi:"sensitiveColumnKey"`
	// The OCID of the sensitive data model.
	SensitiveDataModelId pulumi.StringInput `pulumi:"sensitiveDataModelId"`
}

func (LookupSensitiveDataModelsSensitiveColumnOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSensitiveDataModelsSensitiveColumnArgs)(nil)).Elem()
}

// A collection of values returned by getSensitiveDataModelsSensitiveColumn.
type LookupSensitiveDataModelsSensitiveColumnResultOutput struct{ *pulumi.OutputState }

func (LookupSensitiveDataModelsSensitiveColumnResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSensitiveDataModelsSensitiveColumnResult)(nil)).Elem()
}

func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ToLookupSensitiveDataModelsSensitiveColumnResultOutput() LookupSensitiveDataModelsSensitiveColumnResultOutput {
	return o
}

func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ToLookupSensitiveDataModelsSensitiveColumnResultOutputWithContext(ctx context.Context) LookupSensitiveDataModelsSensitiveColumnResultOutput {
	return o
}

// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) AppDefinedChildColumnKeys() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) []string { return v.AppDefinedChildColumnKeys }).(pulumi.StringArrayOutput)
}

// The name of the application associated with the sensitive column. It's useful when the application name is different from the schema name. Otherwise, it can be ignored.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) AppName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.AppName }).(pulumi.StringOutput)
}

// The composite key groups to which the sensitive column belongs. If the column is part of a composite key, it's assigned a column group. It helps identify and manage referential relationships that involve composite keys.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ColumnGroups() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) []string { return v.ColumnGroups }).(pulumi.StringArrayOutput)
}

// The name of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ColumnName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.ColumnName }).(pulumi.StringOutput)
}

// The data type of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) DataType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.DataType }).(pulumi.StringOutput)
}

// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) DbDefinedChildColumnKeys() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) []string { return v.DbDefinedChildColumnKeys }).(pulumi.StringArrayOutput)
}

// The estimated number of data values the column has in the associated database.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) EstimatedDataValueCount() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.EstimatedDataValueCount }).(pulumi.StringOutput)
}

func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.Id }).(pulumi.StringOutput)
}

// The unique key that identifies the sensitive column. It's numeric and unique within a sensitive data model.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.Key }).(pulumi.StringOutput)
}

// Details about the current state of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The database object that contains the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) Object() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.Object }).(pulumi.StringOutput)
}

// The type of the database object that contains the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ObjectType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.ObjectType }).(pulumi.StringOutput)
}

// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) ParentColumnKeys() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) []string { return v.ParentColumnKeys }).(pulumi.StringArrayOutput)
}

// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) RelationType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.RelationType }).(pulumi.StringOutput)
}

// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) SampleDataValues() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) []string { return v.SampleDataValues }).(pulumi.StringArrayOutput)
}

// The database schema that contains the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) SchemaName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.SchemaName }).(pulumi.StringOutput)
}

func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) SensitiveColumnKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.SensitiveColumnKey }).(pulumi.StringOutput)
}

// The OCID of the sensitive data model that contains the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) SensitiveDataModelId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.SensitiveDataModelId }).(pulumi.StringOutput)
}

// The OCID of the sensitive type associated with the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) SensitiveTypeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.SensitiveTypeId }).(pulumi.StringOutput)
}

// The source of the sensitive column. DISCOVERY indicates that the column was added to the sensitive data model using a data discovery job. MANUAL indicates that the column was added manually.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) Source() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.Source }).(pulumi.StringOutput)
}

// The current state of the sensitive column.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.State }).(pulumi.StringOutput)
}

// The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.Status }).(pulumi.StringOutput)
}

// The date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339), the sensitive column was created in the sensitive data model.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339), the sensitive column was last updated in the sensitive data model.
func (o LookupSensitiveDataModelsSensitiveColumnResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSensitiveDataModelsSensitiveColumnResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSensitiveDataModelsSensitiveColumnResultOutput{})
}