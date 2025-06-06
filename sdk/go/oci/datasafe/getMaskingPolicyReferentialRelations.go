// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Masking Policy Referential Relations in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of referential relations present in the specified masking policy based on the specified query parameters.
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
//			_, err := datasafe.GetMaskingPolicyReferentialRelations(ctx, &datasafe.GetMaskingPolicyReferentialRelationsArgs{
//				MaskingPolicyId: testMaskingPolicy.Id,
//				ColumnNames:     maskingPolicyReferentialRelationColumnName,
//				Objects:         maskingPolicyReferentialRelationObject,
//				RelationTypes:   maskingPolicyReferentialRelationRelationType,
//				SchemaNames:     maskingPolicyReferentialRelationSchemaName,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMaskingPolicyReferentialRelations(ctx *pulumi.Context, args *GetMaskingPolicyReferentialRelationsArgs, opts ...pulumi.InvokeOption) (*GetMaskingPolicyReferentialRelationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMaskingPolicyReferentialRelationsResult
	err := ctx.Invoke("oci:DataSafe/getMaskingPolicyReferentialRelations:getMaskingPolicyReferentialRelations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMaskingPolicyReferentialRelations.
type GetMaskingPolicyReferentialRelationsArgs struct {
	// A filter to return only a specific column based on column name.
	ColumnNames []string                                     `pulumi:"columnNames"`
	Filters     []GetMaskingPolicyReferentialRelationsFilter `pulumi:"filters"`
	// The OCID of the masking policy.
	MaskingPolicyId string `pulumi:"maskingPolicyId"`
	// A filter to return only items related to a specific object name.
	Objects []string `pulumi:"objects"`
	// A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
	RelationTypes []string `pulumi:"relationTypes"`
	// A filter to return only items related to specific schema name.
	SchemaNames []string `pulumi:"schemaNames"`
}

// A collection of values returned by getMaskingPolicyReferentialRelations.
type GetMaskingPolicyReferentialRelationsResult struct {
	ColumnNames []string                                     `pulumi:"columnNames"`
	Filters     []GetMaskingPolicyReferentialRelationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the masking policy that contains the column.
	MaskingPolicyId string `pulumi:"maskingPolicyId"`
	// The list of masking_policy_referential_relation_collection.
	MaskingPolicyReferentialRelationCollections []GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollection `pulumi:"maskingPolicyReferentialRelationCollections"`
	// The name of the object (table or editioning view) that contains the database column(s).
	Objects []string `pulumi:"objects"`
	// The type of referential relationship the column has with its parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationTypes []string `pulumi:"relationTypes"`
	// The name of the schema that contains the database column(s).
	SchemaNames []string `pulumi:"schemaNames"`
}

func GetMaskingPolicyReferentialRelationsOutput(ctx *pulumi.Context, args GetMaskingPolicyReferentialRelationsOutputArgs, opts ...pulumi.InvokeOption) GetMaskingPolicyReferentialRelationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetMaskingPolicyReferentialRelationsResultOutput, error) {
			args := v.(GetMaskingPolicyReferentialRelationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getMaskingPolicyReferentialRelations:getMaskingPolicyReferentialRelations", args, GetMaskingPolicyReferentialRelationsResultOutput{}, options).(GetMaskingPolicyReferentialRelationsResultOutput), nil
		}).(GetMaskingPolicyReferentialRelationsResultOutput)
}

// A collection of arguments for invoking getMaskingPolicyReferentialRelations.
type GetMaskingPolicyReferentialRelationsOutputArgs struct {
	// A filter to return only a specific column based on column name.
	ColumnNames pulumi.StringArrayInput                              `pulumi:"columnNames"`
	Filters     GetMaskingPolicyReferentialRelationsFilterArrayInput `pulumi:"filters"`
	// The OCID of the masking policy.
	MaskingPolicyId pulumi.StringInput `pulumi:"maskingPolicyId"`
	// A filter to return only items related to a specific object name.
	Objects pulumi.StringArrayInput `pulumi:"objects"`
	// A filter to return columns based on their relationship with their parent columns. If set to NONE, it returns the columns that do not have any parent. The response includes the parent columns as well as the independent columns that are not in any relationship. If set to APP_DEFINED, it returns all the child columns that have application-level (non-dictionary) relationship with their parents. If set to DB_DEFINED, it returns all the child columns that have database-level (dictionary-defined) relationship with their parents.
	RelationTypes pulumi.StringArrayInput `pulumi:"relationTypes"`
	// A filter to return only items related to specific schema name.
	SchemaNames pulumi.StringArrayInput `pulumi:"schemaNames"`
}

func (GetMaskingPolicyReferentialRelationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingPolicyReferentialRelationsArgs)(nil)).Elem()
}

// A collection of values returned by getMaskingPolicyReferentialRelations.
type GetMaskingPolicyReferentialRelationsResultOutput struct{ *pulumi.OutputState }

func (GetMaskingPolicyReferentialRelationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMaskingPolicyReferentialRelationsResult)(nil)).Elem()
}

func (o GetMaskingPolicyReferentialRelationsResultOutput) ToGetMaskingPolicyReferentialRelationsResultOutput() GetMaskingPolicyReferentialRelationsResultOutput {
	return o
}

func (o GetMaskingPolicyReferentialRelationsResultOutput) ToGetMaskingPolicyReferentialRelationsResultOutputWithContext(ctx context.Context) GetMaskingPolicyReferentialRelationsResultOutput {
	return o
}

func (o GetMaskingPolicyReferentialRelationsResultOutput) ColumnNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []string { return v.ColumnNames }).(pulumi.StringArrayOutput)
}

func (o GetMaskingPolicyReferentialRelationsResultOutput) Filters() GetMaskingPolicyReferentialRelationsFilterArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []GetMaskingPolicyReferentialRelationsFilter {
		return v.Filters
	}).(GetMaskingPolicyReferentialRelationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMaskingPolicyReferentialRelationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the masking policy that contains the column.
func (o GetMaskingPolicyReferentialRelationsResultOutput) MaskingPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) string { return v.MaskingPolicyId }).(pulumi.StringOutput)
}

// The list of masking_policy_referential_relation_collection.
func (o GetMaskingPolicyReferentialRelationsResultOutput) MaskingPolicyReferentialRelationCollections() GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollection {
		return v.MaskingPolicyReferentialRelationCollections
	}).(GetMaskingPolicyReferentialRelationsMaskingPolicyReferentialRelationCollectionArrayOutput)
}

// The name of the object (table or editioning view) that contains the database column(s).
func (o GetMaskingPolicyReferentialRelationsResultOutput) Objects() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []string { return v.Objects }).(pulumi.StringArrayOutput)
}

// The type of referential relationship the column has with its parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
func (o GetMaskingPolicyReferentialRelationsResultOutput) RelationTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []string { return v.RelationTypes }).(pulumi.StringArrayOutput)
}

// The name of the schema that contains the database column(s).
func (o GetMaskingPolicyReferentialRelationsResultOutput) SchemaNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetMaskingPolicyReferentialRelationsResult) []string { return v.SchemaNames }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMaskingPolicyReferentialRelationsResultOutput{})
}
