// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Sensitive Data Models Sensitive Columns in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of sensitive columns present in the specified sensitive data model based on the specified query parameters.
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
//			_, err := DataSafe.GetSensitiveDataModelsSensitiveColumns(ctx, &datasafe.GetSensitiveDataModelsSensitiveColumnsArgs{
//				SensitiveDataModelId:            oci_data_safe_sensitive_data_model.Test_sensitive_data_model.Id,
//				ColumnGroup:                     pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_column_group),
//				ColumnNames:                     _var.Sensitive_data_models_sensitive_column_column_name,
//				DataTypes:                       _var.Sensitive_data_models_sensitive_column_data_type,
//				Objects:                         _var.Sensitive_data_models_sensitive_column_object,
//				ObjectTypes:                     _var.Sensitive_data_models_sensitive_column_object_type,
//				ParentColumnKeys:                _var.Sensitive_data_models_sensitive_column_parent_column_key,
//				RelationTypes:                   _var.Sensitive_data_models_sensitive_column_relation_type,
//				SchemaNames:                     _var.Sensitive_data_models_sensitive_column_schema_name,
//				SensitiveColumnLifecycleState:   pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_sensitive_column_lifecycle_state),
//				SensitiveTypeIds:                oci_data_safe_sensitive_type.Test_sensitive_type.Id,
//				Statuses:                        _var.Sensitive_data_models_sensitive_column_status,
//				TimeCreatedGreaterThanOrEqualTo: pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_time_created_greater_than_or_equal_to),
//				TimeCreatedLessThan:             pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_time_created_less_than),
//				TimeUpdatedGreaterThanOrEqualTo: pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_time_updated_greater_than_or_equal_to),
//				TimeUpdatedLessThan:             pulumi.StringRef(_var.Sensitive_data_models_sensitive_column_time_updated_less_than),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSensitiveDataModelsSensitiveColumns(ctx *pulumi.Context, args *GetSensitiveDataModelsSensitiveColumnsArgs, opts ...pulumi.InvokeOption) (*GetSensitiveDataModelsSensitiveColumnsResult, error) {
	var rv GetSensitiveDataModelsSensitiveColumnsResult
	err := ctx.Invoke("oci:DataSafe/getSensitiveDataModelsSensitiveColumns:getSensitiveDataModelsSensitiveColumns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSensitiveDataModelsSensitiveColumns.
type GetSensitiveDataModelsSensitiveColumnsArgs struct {
	// A filter to return only the sensitive columns that belong to the specified column group.
	ColumnGroup *string `pulumi:"columnGroup"`
	// A filter to return only a specific column based on column name.
	ColumnNames []string `pulumi:"columnNames"`
	// A filter to return only the resources that match the specified data types.
	DataTypes []string                                       `pulumi:"dataTypes"`
	Filters   []GetSensitiveDataModelsSensitiveColumnsFilter `pulumi:"filters"`
	// A filter to return only items related to a specific object type.
	ObjectTypes []string `pulumi:"objectTypes"`
	// A filter to return only items related to a specific object name.
	Objects []string `pulumi:"objects"`
	// A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
	ParentColumnKeys []string `pulumi:"parentColumnKeys"`
	// A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
	RelationTypes []string `pulumi:"relationTypes"`
	// A filter to return only items related to specific schema name.
	SchemaNames []string `pulumi:"schemaNames"`
	// Filters the sensitive column resources with the given lifecycle state values.
	SensitiveColumnLifecycleState *string `pulumi:"sensitiveColumnLifecycleState"`
	// The OCID of the sensitive data model.
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
	// A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
	SensitiveTypeIds []string `pulumi:"sensitiveTypeIds"`
	// A filter to return only the sensitive columns that match the specified status.
	Statuses []string `pulumi:"statuses"`
	// A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
	TimeCreatedGreaterThanOrEqualTo *string `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	// Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeCreatedLessThan *string `pulumi:"timeCreatedLessThan"`
	// Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdatedGreaterThanOrEqualTo *string `pulumi:"timeUpdatedGreaterThanOrEqualTo"`
	// Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdatedLessThan *string `pulumi:"timeUpdatedLessThan"`
}

// A collection of values returned by getSensitiveDataModelsSensitiveColumns.
type GetSensitiveDataModelsSensitiveColumnsResult struct {
	ColumnGroup *string `pulumi:"columnGroup"`
	// The name of the sensitive column.
	ColumnNames []string `pulumi:"columnNames"`
	// The data type of the sensitive column.
	DataTypes []string                                       `pulumi:"dataTypes"`
	Filters   []GetSensitiveDataModelsSensitiveColumnsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The type of the database object that contains the sensitive column.
	ObjectTypes []string `pulumi:"objectTypes"`
	// The database object that contains the sensitive column.
	Objects          []string `pulumi:"objects"`
	ParentColumnKeys []string `pulumi:"parentColumnKeys"`
	// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationTypes []string `pulumi:"relationTypes"`
	// The database schema that contains the sensitive column.
	SchemaNames []string `pulumi:"schemaNames"`
	// The list of sensitive_column_collection.
	SensitiveColumnCollections    []GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection `pulumi:"sensitiveColumnCollections"`
	SensitiveColumnLifecycleState *string                                                           `pulumi:"sensitiveColumnLifecycleState"`
	// The OCID of the sensitive data model that contains the sensitive column.
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
	// The OCID of the sensitive type associated with the sensitive column.
	SensitiveTypeIds []string `pulumi:"sensitiveTypeIds"`
	// The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
	Statuses                        []string `pulumi:"statuses"`
	TimeCreatedGreaterThanOrEqualTo *string  `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	TimeCreatedLessThan             *string  `pulumi:"timeCreatedLessThan"`
	TimeUpdatedGreaterThanOrEqualTo *string  `pulumi:"timeUpdatedGreaterThanOrEqualTo"`
	TimeUpdatedLessThan             *string  `pulumi:"timeUpdatedLessThan"`
}

func GetSensitiveDataModelsSensitiveColumnsOutput(ctx *pulumi.Context, args GetSensitiveDataModelsSensitiveColumnsOutputArgs, opts ...pulumi.InvokeOption) GetSensitiveDataModelsSensitiveColumnsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSensitiveDataModelsSensitiveColumnsResult, error) {
			args := v.(GetSensitiveDataModelsSensitiveColumnsArgs)
			r, err := GetSensitiveDataModelsSensitiveColumns(ctx, &args, opts...)
			var s GetSensitiveDataModelsSensitiveColumnsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSensitiveDataModelsSensitiveColumnsResultOutput)
}

// A collection of arguments for invoking getSensitiveDataModelsSensitiveColumns.
type GetSensitiveDataModelsSensitiveColumnsOutputArgs struct {
	// A filter to return only the sensitive columns that belong to the specified column group.
	ColumnGroup pulumi.StringPtrInput `pulumi:"columnGroup"`
	// A filter to return only a specific column based on column name.
	ColumnNames pulumi.StringArrayInput `pulumi:"columnNames"`
	// A filter to return only the resources that match the specified data types.
	DataTypes pulumi.StringArrayInput                                `pulumi:"dataTypes"`
	Filters   GetSensitiveDataModelsSensitiveColumnsFilterArrayInput `pulumi:"filters"`
	// A filter to return only items related to a specific object type.
	ObjectTypes pulumi.StringArrayInput `pulumi:"objectTypes"`
	// A filter to return only items related to a specific object name.
	Objects pulumi.StringArrayInput `pulumi:"objects"`
	// A filter to return only the sensitive columns that are children of one of the columns identified by the specified keys.
	ParentColumnKeys pulumi.StringArrayInput `pulumi:"parentColumnKeys"`
	// A filter to return sensitive columns based on their relationship with their parent columns. If set to NONE, it returns the sensitive columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
	RelationTypes pulumi.StringArrayInput `pulumi:"relationTypes"`
	// A filter to return only items related to specific schema name.
	SchemaNames pulumi.StringArrayInput `pulumi:"schemaNames"`
	// Filters the sensitive column resources with the given lifecycle state values.
	SensitiveColumnLifecycleState pulumi.StringPtrInput `pulumi:"sensitiveColumnLifecycleState"`
	// The OCID of the sensitive data model.
	SensitiveDataModelId pulumi.StringInput `pulumi:"sensitiveDataModelId"`
	// A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
	SensitiveTypeIds pulumi.StringArrayInput `pulumi:"sensitiveTypeIds"`
	// A filter to return only the sensitive columns that match the specified status.
	Statuses pulumi.StringArrayInput `pulumi:"statuses"`
	// A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
	TimeCreatedGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	// Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeCreatedLessThan pulumi.StringPtrInput `pulumi:"timeCreatedLessThan"`
	// Search for resources that were updated after a specific date. Specifying this parameter corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdatedGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeUpdatedGreaterThanOrEqualTo"`
	// Search for resources that were updated before a specific date. Specifying this parameter corresponding `timeUpdatedLessThan` parameter will retrieve all resources updated before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdatedLessThan pulumi.StringPtrInput `pulumi:"timeUpdatedLessThan"`
}

func (GetSensitiveDataModelsSensitiveColumnsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSensitiveDataModelsSensitiveColumnsArgs)(nil)).Elem()
}

// A collection of values returned by getSensitiveDataModelsSensitiveColumns.
type GetSensitiveDataModelsSensitiveColumnsResultOutput struct{ *pulumi.OutputState }

func (GetSensitiveDataModelsSensitiveColumnsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSensitiveDataModelsSensitiveColumnsResult)(nil)).Elem()
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ToGetSensitiveDataModelsSensitiveColumnsResultOutput() GetSensitiveDataModelsSensitiveColumnsResultOutput {
	return o
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ToGetSensitiveDataModelsSensitiveColumnsResultOutputWithContext(ctx context.Context) GetSensitiveDataModelsSensitiveColumnsResultOutput {
	return o
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ColumnGroup() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.ColumnGroup }).(pulumi.StringPtrOutput)
}

// The name of the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ColumnNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.ColumnNames }).(pulumi.StringArrayOutput)
}

// The data type of the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) DataTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.DataTypes }).(pulumi.StringArrayOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) Filters() GetSensitiveDataModelsSensitiveColumnsFilterArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []GetSensitiveDataModelsSensitiveColumnsFilter {
		return v.Filters
	}).(GetSensitiveDataModelsSensitiveColumnsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The type of the database object that contains the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ObjectTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.ObjectTypes }).(pulumi.StringArrayOutput)
}

// The database object that contains the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) Objects() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.Objects }).(pulumi.StringArrayOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) ParentColumnKeys() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.ParentColumnKeys }).(pulumi.StringArrayOutput)
}

// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) RelationTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.RelationTypes }).(pulumi.StringArrayOutput)
}

// The database schema that contains the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) SchemaNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.SchemaNames }).(pulumi.StringArrayOutput)
}

// The list of sensitive_column_collection.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) SensitiveColumnCollections() GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection {
		return v.SensitiveColumnCollections
	}).(GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionArrayOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) SensitiveColumnLifecycleState() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.SensitiveColumnLifecycleState }).(pulumi.StringPtrOutput)
}

// The OCID of the sensitive data model that contains the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) SensitiveDataModelId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) string { return v.SensitiveDataModelId }).(pulumi.StringOutput)
}

// The OCID of the sensitive type associated with the sensitive column.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) SensitiveTypeIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.SensitiveTypeIds }).(pulumi.StringArrayOutput)
}

// The status of the sensitive column. VALID means the column is considered sensitive. INVALID means the column is not considered sensitive. Tracking invalid columns in a sensitive data model helps ensure that an incremental data discovery job does not identify these columns as sensitive again.
func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) Statuses() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) []string { return v.Statuses }).(pulumi.StringArrayOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) TimeCreatedGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.TimeCreatedGreaterThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) TimeCreatedLessThan() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.TimeCreatedLessThan }).(pulumi.StringPtrOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) TimeUpdatedGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.TimeUpdatedGreaterThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetSensitiveDataModelsSensitiveColumnsResultOutput) TimeUpdatedLessThan() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSensitiveDataModelsSensitiveColumnsResult) *string { return v.TimeUpdatedLessThan }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSensitiveDataModelsSensitiveColumnsResultOutput{})
}