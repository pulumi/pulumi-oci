// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Discovery Job resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified discovery job.
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
//			_, err := datasafe.GetDiscoveryJob(ctx, &datasafe.GetDiscoveryJobArgs{
//				DiscoveryJobId: testDiscoveryJobOciDataSafeDiscoveryJob.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDiscoveryJob(ctx *pulumi.Context, args *GetDiscoveryJobArgs, opts ...pulumi.InvokeOption) (*GetDiscoveryJobResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDiscoveryJobResult
	err := ctx.Invoke("oci:DataSafe/getDiscoveryJob:getDiscoveryJob", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDiscoveryJob.
type GetDiscoveryJobArgs struct {
	// The OCID of the discovery job.
	DiscoveryJobId string `pulumi:"discoveryJobId"`
}

// A collection of values returned by getDiscoveryJob.
type GetDiscoveryJobResult struct {
	// The OCID of the compartment that contains the discovery job.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags    map[string]string `pulumi:"definedTags"`
	DiscoveryJobId string            `pulumi:"discoveryJobId"`
	// The type of the discovery job. It defines the job's scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
	DiscoveryType string `pulumi:"discoveryType"`
	// The display name of the discovery job.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the discovery job.
	Id string `pulumi:"id"`
	// Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
	IsAppDefinedRelationDiscoveryEnabled bool `pulumi:"isAppDefinedRelationDiscoveryEnabled"`
	// Indicates if all the schemas in the associated target database are used for data discovery. If it is set to true, sensitive data is discovered in all schemas (except for schemas maintained by Oracle).
	IsIncludeAllSchemas bool `pulumi:"isIncludeAllSchemas"`
	// Indicates if all the existing sensitive types are used for data discovery. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
	IsIncludeAllSensitiveTypes bool `pulumi:"isIncludeAllSensitiveTypes"`
	// Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
	IsSampleDataCollectionEnabled bool `pulumi:"isSampleDataCollectionEnabled"`
	// The schemas used for data discovery.
	SchemasForDiscoveries []string `pulumi:"schemasForDiscoveries"`
	// The OCID of the sensitive data model associated with the discovery job.
	SensitiveDataModelId string `pulumi:"sensitiveDataModelId"`
	// The OCIDs of the sensitive type groups to be used by data discovery jobs.
	SensitiveTypeGroupIdsForDiscoveries []string `pulumi:"sensitiveTypeGroupIdsForDiscoveries"`
	// The OCIDs of the sensitive types used for data discovery.
	SensitiveTypeIdsForDiscoveries []string `pulumi:"sensitiveTypeIdsForDiscoveries"`
	// The current state of the discovery job.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The data discovery jobs will scan the tables specified here, including both schemas and tables.
	TablesForDiscoveries []GetDiscoveryJobTablesForDiscovery `pulumi:"tablesForDiscoveries"`
	// The OCID of the target database associated with the discovery job.
	TargetId string `pulumi:"targetId"`
	// The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
	TimeFinished string `pulumi:"timeFinished"`
	// The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeStarted string `pulumi:"timeStarted"`
	// The total number of columns scanned by the discovery job.
	TotalColumnsScanned string `pulumi:"totalColumnsScanned"`
	// The total number of deleted sensitive columns identified by the discovery job.
	TotalDeletedSensitiveColumns string `pulumi:"totalDeletedSensitiveColumns"`
	// The total number of modified sensitive columns identified by the discovery job.
	TotalModifiedSensitiveColumns string `pulumi:"totalModifiedSensitiveColumns"`
	// The total number of new sensitive columns identified by the discovery job.
	TotalNewSensitiveColumns string `pulumi:"totalNewSensitiveColumns"`
	// The total number of objects (tables and editioning views) scanned by the discovery job.
	TotalObjectsScanned string `pulumi:"totalObjectsScanned"`
	// The total number of schemas scanned by the discovery job.
	TotalSchemasScanned string `pulumi:"totalSchemasScanned"`
}

func GetDiscoveryJobOutput(ctx *pulumi.Context, args GetDiscoveryJobOutputArgs, opts ...pulumi.InvokeOption) GetDiscoveryJobResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDiscoveryJobResultOutput, error) {
			args := v.(GetDiscoveryJobArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getDiscoveryJob:getDiscoveryJob", args, GetDiscoveryJobResultOutput{}, options).(GetDiscoveryJobResultOutput), nil
		}).(GetDiscoveryJobResultOutput)
}

// A collection of arguments for invoking getDiscoveryJob.
type GetDiscoveryJobOutputArgs struct {
	// The OCID of the discovery job.
	DiscoveryJobId pulumi.StringInput `pulumi:"discoveryJobId"`
}

func (GetDiscoveryJobOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDiscoveryJobArgs)(nil)).Elem()
}

// A collection of values returned by getDiscoveryJob.
type GetDiscoveryJobResultOutput struct{ *pulumi.OutputState }

func (GetDiscoveryJobResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDiscoveryJobResult)(nil)).Elem()
}

func (o GetDiscoveryJobResultOutput) ToGetDiscoveryJobResultOutput() GetDiscoveryJobResultOutput {
	return o
}

func (o GetDiscoveryJobResultOutput) ToGetDiscoveryJobResultOutputWithContext(ctx context.Context) GetDiscoveryJobResultOutput {
	return o
}

// The OCID of the compartment that contains the discovery job.
func (o GetDiscoveryJobResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o GetDiscoveryJobResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

func (o GetDiscoveryJobResultOutput) DiscoveryJobId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.DiscoveryJobId }).(pulumi.StringOutput)
}

// The type of the discovery job. It defines the job's scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
func (o GetDiscoveryJobResultOutput) DiscoveryType() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.DiscoveryType }).(pulumi.StringOutput)
}

// The display name of the discovery job.
func (o GetDiscoveryJobResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o GetDiscoveryJobResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the discovery job.
func (o GetDiscoveryJobResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It's disabled by default and should be used only if there is a need to identify application-level relationships.
func (o GetDiscoveryJobResultOutput) IsAppDefinedRelationDiscoveryEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) bool { return v.IsAppDefinedRelationDiscoveryEnabled }).(pulumi.BoolOutput)
}

// Indicates if all the schemas in the associated target database are used for data discovery. If it is set to true, sensitive data is discovered in all schemas (except for schemas maintained by Oracle).
func (o GetDiscoveryJobResultOutput) IsIncludeAllSchemas() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) bool { return v.IsIncludeAllSchemas }).(pulumi.BoolOutput)
}

// Indicates if all the existing sensitive types are used for data discovery. If it's set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
func (o GetDiscoveryJobResultOutput) IsIncludeAllSensitiveTypes() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) bool { return v.IsIncludeAllSensitiveTypes }).(pulumi.BoolOutput)
}

// Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it's disabled by default and should be used only if it's acceptable to store sample data in Data Safe's repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
func (o GetDiscoveryJobResultOutput) IsSampleDataCollectionEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) bool { return v.IsSampleDataCollectionEnabled }).(pulumi.BoolOutput)
}

// The schemas used for data discovery.
func (o GetDiscoveryJobResultOutput) SchemasForDiscoveries() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) []string { return v.SchemasForDiscoveries }).(pulumi.StringArrayOutput)
}

// The OCID of the sensitive data model associated with the discovery job.
func (o GetDiscoveryJobResultOutput) SensitiveDataModelId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.SensitiveDataModelId }).(pulumi.StringOutput)
}

// The OCIDs of the sensitive type groups to be used by data discovery jobs.
func (o GetDiscoveryJobResultOutput) SensitiveTypeGroupIdsForDiscoveries() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) []string { return v.SensitiveTypeGroupIdsForDiscoveries }).(pulumi.StringArrayOutput)
}

// The OCIDs of the sensitive types used for data discovery.
func (o GetDiscoveryJobResultOutput) SensitiveTypeIdsForDiscoveries() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) []string { return v.SensitiveTypeIdsForDiscoveries }).(pulumi.StringArrayOutput)
}

// The current state of the discovery job.
func (o GetDiscoveryJobResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetDiscoveryJobResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The data discovery jobs will scan the tables specified here, including both schemas and tables.
func (o GetDiscoveryJobResultOutput) TablesForDiscoveries() GetDiscoveryJobTablesForDiscoveryArrayOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) []GetDiscoveryJobTablesForDiscovery { return v.TablesForDiscoveries }).(GetDiscoveryJobTablesForDiscoveryArrayOutput)
}

// The OCID of the target database associated with the discovery job.
func (o GetDiscoveryJobResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
func (o GetDiscoveryJobResultOutput) TimeFinished() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TimeFinished }).(pulumi.StringOutput)
}

// The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o GetDiscoveryJobResultOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TimeStarted }).(pulumi.StringOutput)
}

// The total number of columns scanned by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalColumnsScanned() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalColumnsScanned }).(pulumi.StringOutput)
}

// The total number of deleted sensitive columns identified by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalDeletedSensitiveColumns() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalDeletedSensitiveColumns }).(pulumi.StringOutput)
}

// The total number of modified sensitive columns identified by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalModifiedSensitiveColumns() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalModifiedSensitiveColumns }).(pulumi.StringOutput)
}

// The total number of new sensitive columns identified by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalNewSensitiveColumns() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalNewSensitiveColumns }).(pulumi.StringOutput)
}

// The total number of objects (tables and editioning views) scanned by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalObjectsScanned() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalObjectsScanned }).(pulumi.StringOutput)
}

// The total number of schemas scanned by the discovery job.
func (o GetDiscoveryJobResultOutput) TotalSchemasScanned() pulumi.StringOutput {
	return o.ApplyT(func(v GetDiscoveryJobResult) string { return v.TotalSchemasScanned }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDiscoveryJobResultOutput{})
}
