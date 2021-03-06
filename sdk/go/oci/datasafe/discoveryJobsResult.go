// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Discovery Jobs Result resource in Oracle Cloud Infrastructure Data Safe service.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DataSafe.NewDiscoveryJobsResult(ctx, "testDiscoveryJobsResult", nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// DiscoveryJobsResults can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:DataSafe/discoveryJobsResult:DiscoveryJobsResult test_discovery_jobs_result "discoveryJobs/{discoveryJobId}/results/{resultKey}"
// ```
type DiscoveryJobsResult struct {
	pulumi.CustomResourceState

	// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
	AppDefinedChildColumnKeys pulumi.StringArrayOutput `pulumi:"appDefinedChildColumnKeys"`
	// The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
	AppName pulumi.StringOutput `pulumi:"appName"`
	// The name of the sensitive column.
	ColumnName pulumi.StringOutput `pulumi:"columnName"`
	// The data type of the sensitive column.
	DataType pulumi.StringOutput `pulumi:"dataType"`
	// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
	DbDefinedChildColumnKeys pulumi.StringArrayOutput `pulumi:"dbDefinedChildColumnKeys"`
	DiscoveryJobId           pulumi.StringOutput      `pulumi:"discoveryJobId"`
	// The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
	DiscoveryType pulumi.StringOutput `pulumi:"discoveryType"`
	// The estimated number of data values the column has in the associated database.
	EstimatedDataValueCount pulumi.StringOutput `pulumi:"estimatedDataValueCount"`
	// Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
	IsResultApplied pulumi.BoolOutput `pulumi:"isResultApplied"`
	// The unique key that identifies the discovery result.
	Key pulumi.StringOutput `pulumi:"key"`
	// The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
	ModifiedAttributes DiscoveryJobsResultModifiedAttributeArrayOutput `pulumi:"modifiedAttributes"`
	// The database object that contains the sensitive column.
	Object pulumi.StringOutput `pulumi:"object"`
	// The type of the database object that contains the sensitive column.
	ObjectType pulumi.StringOutput `pulumi:"objectType"`
	// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
	ParentColumnKeys pulumi.StringArrayOutput `pulumi:"parentColumnKeys"`
	// Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
	PlannedAction pulumi.StringOutput `pulumi:"plannedAction"`
	// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationType pulumi.StringOutput `pulumi:"relationType"`
	// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
	SampleDataValues pulumi.StringArrayOutput `pulumi:"sampleDataValues"`
	// The database schema that contains the sensitive column.
	SchemaName pulumi.StringOutput `pulumi:"schemaName"`
	// The unique key that identifies the sensitive column represented by the discovery result.
	SensitiveColumnkey pulumi.StringOutput `pulumi:"sensitiveColumnkey"`
	// The OCID of the sensitive type associated with the sensitive column.
	SensitiveTypeId pulumi.StringOutput `pulumi:"sensitiveTypeId"`
}

// NewDiscoveryJobsResult registers a new resource with the given unique name, arguments, and options.
func NewDiscoveryJobsResult(ctx *pulumi.Context,
	name string, args *DiscoveryJobsResultArgs, opts ...pulumi.ResourceOption) (*DiscoveryJobsResult, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DiscoveryJobId == nil {
		return nil, errors.New("invalid value for required argument 'DiscoveryJobId'")
	}
	var resource DiscoveryJobsResult
	err := ctx.RegisterResource("oci:DataSafe/discoveryJobsResult:DiscoveryJobsResult", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDiscoveryJobsResult gets an existing DiscoveryJobsResult resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDiscoveryJobsResult(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DiscoveryJobsResultState, opts ...pulumi.ResourceOption) (*DiscoveryJobsResult, error) {
	var resource DiscoveryJobsResult
	err := ctx.ReadResource("oci:DataSafe/discoveryJobsResult:DiscoveryJobsResult", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DiscoveryJobsResult resources.
type discoveryJobsResultState struct {
	// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
	AppDefinedChildColumnKeys []string `pulumi:"appDefinedChildColumnKeys"`
	// The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
	AppName *string `pulumi:"appName"`
	// The name of the sensitive column.
	ColumnName *string `pulumi:"columnName"`
	// The data type of the sensitive column.
	DataType *string `pulumi:"dataType"`
	// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
	DbDefinedChildColumnKeys []string `pulumi:"dbDefinedChildColumnKeys"`
	DiscoveryJobId           *string  `pulumi:"discoveryJobId"`
	// The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
	DiscoveryType *string `pulumi:"discoveryType"`
	// The estimated number of data values the column has in the associated database.
	EstimatedDataValueCount *string `pulumi:"estimatedDataValueCount"`
	// Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
	IsResultApplied *bool `pulumi:"isResultApplied"`
	// The unique key that identifies the discovery result.
	Key *string `pulumi:"key"`
	// The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
	ModifiedAttributes []DiscoveryJobsResultModifiedAttribute `pulumi:"modifiedAttributes"`
	// The database object that contains the sensitive column.
	Object *string `pulumi:"object"`
	// The type of the database object that contains the sensitive column.
	ObjectType *string `pulumi:"objectType"`
	// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
	ParentColumnKeys []string `pulumi:"parentColumnKeys"`
	// Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
	PlannedAction *string `pulumi:"plannedAction"`
	// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationType *string `pulumi:"relationType"`
	// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
	SampleDataValues []string `pulumi:"sampleDataValues"`
	// The database schema that contains the sensitive column.
	SchemaName *string `pulumi:"schemaName"`
	// The unique key that identifies the sensitive column represented by the discovery result.
	SensitiveColumnkey *string `pulumi:"sensitiveColumnkey"`
	// The OCID of the sensitive type associated with the sensitive column.
	SensitiveTypeId *string `pulumi:"sensitiveTypeId"`
}

type DiscoveryJobsResultState struct {
	// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
	AppDefinedChildColumnKeys pulumi.StringArrayInput
	// The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
	AppName pulumi.StringPtrInput
	// The name of the sensitive column.
	ColumnName pulumi.StringPtrInput
	// The data type of the sensitive column.
	DataType pulumi.StringPtrInput
	// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
	DbDefinedChildColumnKeys pulumi.StringArrayInput
	DiscoveryJobId           pulumi.StringPtrInput
	// The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
	DiscoveryType pulumi.StringPtrInput
	// The estimated number of data values the column has in the associated database.
	EstimatedDataValueCount pulumi.StringPtrInput
	// Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
	IsResultApplied pulumi.BoolPtrInput
	// The unique key that identifies the discovery result.
	Key pulumi.StringPtrInput
	// The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
	ModifiedAttributes DiscoveryJobsResultModifiedAttributeArrayInput
	// The database object that contains the sensitive column.
	Object pulumi.StringPtrInput
	// The type of the database object that contains the sensitive column.
	ObjectType pulumi.StringPtrInput
	// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
	ParentColumnKeys pulumi.StringArrayInput
	// Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
	PlannedAction pulumi.StringPtrInput
	// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
	RelationType pulumi.StringPtrInput
	// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
	SampleDataValues pulumi.StringArrayInput
	// The database schema that contains the sensitive column.
	SchemaName pulumi.StringPtrInput
	// The unique key that identifies the sensitive column represented by the discovery result.
	SensitiveColumnkey pulumi.StringPtrInput
	// The OCID of the sensitive type associated with the sensitive column.
	SensitiveTypeId pulumi.StringPtrInput
}

func (DiscoveryJobsResultState) ElementType() reflect.Type {
	return reflect.TypeOf((*discoveryJobsResultState)(nil)).Elem()
}

type discoveryJobsResultArgs struct {
	DiscoveryJobId string `pulumi:"discoveryJobId"`
}

// The set of arguments for constructing a DiscoveryJobsResult resource.
type DiscoveryJobsResultArgs struct {
	DiscoveryJobId pulumi.StringInput
}

func (DiscoveryJobsResultArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*discoveryJobsResultArgs)(nil)).Elem()
}

type DiscoveryJobsResultInput interface {
	pulumi.Input

	ToDiscoveryJobsResultOutput() DiscoveryJobsResultOutput
	ToDiscoveryJobsResultOutputWithContext(ctx context.Context) DiscoveryJobsResultOutput
}

func (*DiscoveryJobsResult) ElementType() reflect.Type {
	return reflect.TypeOf((**DiscoveryJobsResult)(nil)).Elem()
}

func (i *DiscoveryJobsResult) ToDiscoveryJobsResultOutput() DiscoveryJobsResultOutput {
	return i.ToDiscoveryJobsResultOutputWithContext(context.Background())
}

func (i *DiscoveryJobsResult) ToDiscoveryJobsResultOutputWithContext(ctx context.Context) DiscoveryJobsResultOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobsResultOutput)
}

// DiscoveryJobsResultArrayInput is an input type that accepts DiscoveryJobsResultArray and DiscoveryJobsResultArrayOutput values.
// You can construct a concrete instance of `DiscoveryJobsResultArrayInput` via:
//
//          DiscoveryJobsResultArray{ DiscoveryJobsResultArgs{...} }
type DiscoveryJobsResultArrayInput interface {
	pulumi.Input

	ToDiscoveryJobsResultArrayOutput() DiscoveryJobsResultArrayOutput
	ToDiscoveryJobsResultArrayOutputWithContext(context.Context) DiscoveryJobsResultArrayOutput
}

type DiscoveryJobsResultArray []DiscoveryJobsResultInput

func (DiscoveryJobsResultArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DiscoveryJobsResult)(nil)).Elem()
}

func (i DiscoveryJobsResultArray) ToDiscoveryJobsResultArrayOutput() DiscoveryJobsResultArrayOutput {
	return i.ToDiscoveryJobsResultArrayOutputWithContext(context.Background())
}

func (i DiscoveryJobsResultArray) ToDiscoveryJobsResultArrayOutputWithContext(ctx context.Context) DiscoveryJobsResultArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobsResultArrayOutput)
}

// DiscoveryJobsResultMapInput is an input type that accepts DiscoveryJobsResultMap and DiscoveryJobsResultMapOutput values.
// You can construct a concrete instance of `DiscoveryJobsResultMapInput` via:
//
//          DiscoveryJobsResultMap{ "key": DiscoveryJobsResultArgs{...} }
type DiscoveryJobsResultMapInput interface {
	pulumi.Input

	ToDiscoveryJobsResultMapOutput() DiscoveryJobsResultMapOutput
	ToDiscoveryJobsResultMapOutputWithContext(context.Context) DiscoveryJobsResultMapOutput
}

type DiscoveryJobsResultMap map[string]DiscoveryJobsResultInput

func (DiscoveryJobsResultMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DiscoveryJobsResult)(nil)).Elem()
}

func (i DiscoveryJobsResultMap) ToDiscoveryJobsResultMapOutput() DiscoveryJobsResultMapOutput {
	return i.ToDiscoveryJobsResultMapOutputWithContext(context.Background())
}

func (i DiscoveryJobsResultMap) ToDiscoveryJobsResultMapOutputWithContext(ctx context.Context) DiscoveryJobsResultMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DiscoveryJobsResultMapOutput)
}

type DiscoveryJobsResultOutput struct{ *pulumi.OutputState }

func (DiscoveryJobsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DiscoveryJobsResult)(nil)).Elem()
}

func (o DiscoveryJobsResultOutput) ToDiscoveryJobsResultOutput() DiscoveryJobsResultOutput {
	return o
}

func (o DiscoveryJobsResultOutput) ToDiscoveryJobsResultOutputWithContext(ctx context.Context) DiscoveryJobsResultOutput {
	return o
}

type DiscoveryJobsResultArrayOutput struct{ *pulumi.OutputState }

func (DiscoveryJobsResultArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DiscoveryJobsResult)(nil)).Elem()
}

func (o DiscoveryJobsResultArrayOutput) ToDiscoveryJobsResultArrayOutput() DiscoveryJobsResultArrayOutput {
	return o
}

func (o DiscoveryJobsResultArrayOutput) ToDiscoveryJobsResultArrayOutputWithContext(ctx context.Context) DiscoveryJobsResultArrayOutput {
	return o
}

func (o DiscoveryJobsResultArrayOutput) Index(i pulumi.IntInput) DiscoveryJobsResultOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DiscoveryJobsResult {
		return vs[0].([]*DiscoveryJobsResult)[vs[1].(int)]
	}).(DiscoveryJobsResultOutput)
}

type DiscoveryJobsResultMapOutput struct{ *pulumi.OutputState }

func (DiscoveryJobsResultMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DiscoveryJobsResult)(nil)).Elem()
}

func (o DiscoveryJobsResultMapOutput) ToDiscoveryJobsResultMapOutput() DiscoveryJobsResultMapOutput {
	return o
}

func (o DiscoveryJobsResultMapOutput) ToDiscoveryJobsResultMapOutputWithContext(ctx context.Context) DiscoveryJobsResultMapOutput {
	return o
}

func (o DiscoveryJobsResultMapOutput) MapIndex(k pulumi.StringInput) DiscoveryJobsResultOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DiscoveryJobsResult {
		return vs[0].(map[string]*DiscoveryJobsResult)[vs[1].(string)]
	}).(DiscoveryJobsResultOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobsResultInput)(nil)).Elem(), &DiscoveryJobsResult{})
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobsResultArrayInput)(nil)).Elem(), DiscoveryJobsResultArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DiscoveryJobsResultMapInput)(nil)).Elem(), DiscoveryJobsResultMap{})
	pulumi.RegisterOutputType(DiscoveryJobsResultOutput{})
	pulumi.RegisterOutputType(DiscoveryJobsResultArrayOutput{})
	pulumi.RegisterOutputType(DiscoveryJobsResultMapOutput{})
}
