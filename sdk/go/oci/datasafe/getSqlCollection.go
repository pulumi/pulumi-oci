// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Sql Collection resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a SQL collection by identifier.
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
//			_, err := DataSafe.GetSqlCollection(ctx, &datasafe.GetSqlCollectionArgs{
//				SqlCollectionId: oci_data_safe_sql_collection.Test_sql_collection.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSqlCollection(ctx *pulumi.Context, args *LookupSqlCollectionArgs, opts ...pulumi.InvokeOption) (*LookupSqlCollectionResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSqlCollectionResult
	err := ctx.Invoke("oci:DataSafe/getSqlCollection:getSqlCollection", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSqlCollection.
type LookupSqlCollectionArgs struct {
	// The OCID of the SQL collection resource.
	SqlCollectionId string `pulumi:"sqlCollectionId"`
}

// A collection of values returned by getSqlCollection.
type LookupSqlCollectionResult struct {
	// The OCID of the compartment containing the SQL collection.
	CompartmentId string `pulumi:"compartmentId"`
	// The database user name.
	DbUserName string `pulumi:"dbUserName"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The description of the SQL collection.
	Description string `pulumi:"description"`
	// The display name of the SQL collection.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags                     map[string]interface{} `pulumi:"freeformTags"`
	GenerateSqlFirewallPolicyTrigger bool                   `pulumi:"generateSqlFirewallPolicyTrigger"`
	// The OCID of the SQL collection.
	Id string `pulumi:"id"`
	// Details about the current state of the SQL collection in Data Safe.
	LifecycleDetails          string `pulumi:"lifecycleDetails"`
	PurgeLogsTrigger          bool   `pulumi:"purgeLogsTrigger"`
	RefreshLogInsightsTrigger bool   `pulumi:"refreshLogInsightsTrigger"`
	SqlCollectionId           string `pulumi:"sqlCollectionId"`
	// Specifies the level of SQL that will be collected. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
	SqlLevel     string `pulumi:"sqlLevel"`
	StartTrigger bool   `pulumi:"startTrigger"`
	// The current state of the SQL collection.
	State string `pulumi:"state"`
	// Specifies if the status of the SqlCollection. Enabled indicates that the collecting is in progress.
	Status      string `pulumi:"status"`
	StopTrigger bool   `pulumi:"stopTrigger"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The OCID of the target corresponding to the security policy deployment.
	TargetId string `pulumi:"targetId"`
	// The time that the SQL collection was created, in the format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The timestamp of the most recent SqlCollection start operation, in the format defined by RFC3339.
	TimeLastStarted string `pulumi:"timeLastStarted"`
	// The timestamp of the most recent SqlCollection stop operation, in the format defined by RFC3339.
	TimeLastStopped string `pulumi:"timeLastStopped"`
	// The last date and time the SQL collection was updated, in the format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupSqlCollectionOutput(ctx *pulumi.Context, args LookupSqlCollectionOutputArgs, opts ...pulumi.InvokeOption) LookupSqlCollectionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupSqlCollectionResult, error) {
			args := v.(LookupSqlCollectionArgs)
			r, err := LookupSqlCollection(ctx, &args, opts...)
			var s LookupSqlCollectionResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupSqlCollectionResultOutput)
}

// A collection of arguments for invoking getSqlCollection.
type LookupSqlCollectionOutputArgs struct {
	// The OCID of the SQL collection resource.
	SqlCollectionId pulumi.StringInput `pulumi:"sqlCollectionId"`
}

func (LookupSqlCollectionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSqlCollectionArgs)(nil)).Elem()
}

// A collection of values returned by getSqlCollection.
type LookupSqlCollectionResultOutput struct{ *pulumi.OutputState }

func (LookupSqlCollectionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSqlCollectionResult)(nil)).Elem()
}

func (o LookupSqlCollectionResultOutput) ToLookupSqlCollectionResultOutput() LookupSqlCollectionResultOutput {
	return o
}

func (o LookupSqlCollectionResultOutput) ToLookupSqlCollectionResultOutputWithContext(ctx context.Context) LookupSqlCollectionResultOutput {
	return o
}

func (o LookupSqlCollectionResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupSqlCollectionResult] {
	return pulumix.Output[LookupSqlCollectionResult]{
		OutputState: o.OutputState,
	}
}

// The OCID of the compartment containing the SQL collection.
func (o LookupSqlCollectionResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The database user name.
func (o LookupSqlCollectionResultOutput) DbUserName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.DbUserName }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o LookupSqlCollectionResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The description of the SQL collection.
func (o LookupSqlCollectionResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the SQL collection.
func (o LookupSqlCollectionResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupSqlCollectionResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

func (o LookupSqlCollectionResultOutput) GenerateSqlFirewallPolicyTrigger() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) bool { return v.GenerateSqlFirewallPolicyTrigger }).(pulumi.BoolOutput)
}

// The OCID of the SQL collection.
func (o LookupSqlCollectionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.Id }).(pulumi.StringOutput)
}

// Details about the current state of the SQL collection in Data Safe.
func (o LookupSqlCollectionResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupSqlCollectionResultOutput) PurgeLogsTrigger() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) bool { return v.PurgeLogsTrigger }).(pulumi.BoolOutput)
}

func (o LookupSqlCollectionResultOutput) RefreshLogInsightsTrigger() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) bool { return v.RefreshLogInsightsTrigger }).(pulumi.BoolOutput)
}

func (o LookupSqlCollectionResultOutput) SqlCollectionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.SqlCollectionId }).(pulumi.StringOutput)
}

// Specifies the level of SQL that will be collected. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
func (o LookupSqlCollectionResultOutput) SqlLevel() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.SqlLevel }).(pulumi.StringOutput)
}

func (o LookupSqlCollectionResultOutput) StartTrigger() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) bool { return v.StartTrigger }).(pulumi.BoolOutput)
}

// The current state of the SQL collection.
func (o LookupSqlCollectionResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.State }).(pulumi.StringOutput)
}

// Specifies if the status of the SqlCollection. Enabled indicates that the collecting is in progress.
func (o LookupSqlCollectionResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.Status }).(pulumi.StringOutput)
}

func (o LookupSqlCollectionResultOutput) StopTrigger() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) bool { return v.StopTrigger }).(pulumi.BoolOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupSqlCollectionResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The OCID of the target corresponding to the security policy deployment.
func (o LookupSqlCollectionResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// The time that the SQL collection was created, in the format defined by RFC3339.
func (o LookupSqlCollectionResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The timestamp of the most recent SqlCollection start operation, in the format defined by RFC3339.
func (o LookupSqlCollectionResultOutput) TimeLastStarted() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.TimeLastStarted }).(pulumi.StringOutput)
}

// The timestamp of the most recent SqlCollection stop operation, in the format defined by RFC3339.
func (o LookupSqlCollectionResultOutput) TimeLastStopped() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.TimeLastStopped }).(pulumi.StringOutput)
}

// The last date and time the SQL collection was updated, in the format defined by RFC3339.
func (o LookupSqlCollectionResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSqlCollectionResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSqlCollectionResultOutput{})
}