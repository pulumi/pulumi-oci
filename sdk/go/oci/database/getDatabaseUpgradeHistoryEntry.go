// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Database Upgrade History Entry resource in Oracle Cloud Infrastructure Database service.
//
// gets the upgrade history for a specified database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.GetDatabaseUpgradeHistoryEntry(ctx, &database.GetDatabaseUpgradeHistoryEntryArgs{
//				DatabaseId:            oci_database_database.Test_database.Id,
//				UpgradeHistoryEntryId: oci_database_upgrade_history_entry.Test_upgrade_history_entry.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDatabaseUpgradeHistoryEntry(ctx *pulumi.Context, args *GetDatabaseUpgradeHistoryEntryArgs, opts ...pulumi.InvokeOption) (*GetDatabaseUpgradeHistoryEntryResult, error) {
	var rv GetDatabaseUpgradeHistoryEntryResult
	err := ctx.Invoke("oci:Database/getDatabaseUpgradeHistoryEntry:getDatabaseUpgradeHistoryEntry", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDatabaseUpgradeHistoryEntry.
type GetDatabaseUpgradeHistoryEntryArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DatabaseId string `pulumi:"databaseId"`
	// The database/db system upgrade History [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	UpgradeHistoryEntryId string `pulumi:"upgradeHistoryEntryId"`
}

// A collection of values returned by getDatabaseUpgradeHistoryEntry.
type GetDatabaseUpgradeHistoryEntryResult struct {
	// The database upgrade action.
	Action     string `pulumi:"action"`
	DatabaseId string `pulumi:"databaseId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: "-upgradeTimezone false -keepEvents"
	Options string `pulumi:"options"`
	// The source of the Oracle Database software to be used for the upgrade.
	// * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
	// * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
	Source string `pulumi:"source"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
	SourceDbHomeId string `pulumi:"sourceDbHomeId"`
	// Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
	State string `pulumi:"state"`
	// the database software image used for upgrading database.
	TargetDatabaseSoftwareImageId string `pulumi:"targetDatabaseSoftwareImageId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
	TargetDbHomeId string `pulumi:"targetDbHomeId"`
	// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
	TargetDbVersion string `pulumi:"targetDbVersion"`
	// The date and time when the database upgrade ended.
	TimeEnded string `pulumi:"timeEnded"`
	// The date and time when the database upgrade started.
	TimeStarted           string `pulumi:"timeStarted"`
	UpgradeHistoryEntryId string `pulumi:"upgradeHistoryEntryId"`
}

func GetDatabaseUpgradeHistoryEntryOutput(ctx *pulumi.Context, args GetDatabaseUpgradeHistoryEntryOutputArgs, opts ...pulumi.InvokeOption) GetDatabaseUpgradeHistoryEntryResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDatabaseUpgradeHistoryEntryResult, error) {
			args := v.(GetDatabaseUpgradeHistoryEntryArgs)
			r, err := GetDatabaseUpgradeHistoryEntry(ctx, &args, opts...)
			var s GetDatabaseUpgradeHistoryEntryResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDatabaseUpgradeHistoryEntryResultOutput)
}

// A collection of arguments for invoking getDatabaseUpgradeHistoryEntry.
type GetDatabaseUpgradeHistoryEntryOutputArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DatabaseId pulumi.StringInput `pulumi:"databaseId"`
	// The database/db system upgrade History [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	UpgradeHistoryEntryId pulumi.StringInput `pulumi:"upgradeHistoryEntryId"`
}

func (GetDatabaseUpgradeHistoryEntryOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabaseUpgradeHistoryEntryArgs)(nil)).Elem()
}

// A collection of values returned by getDatabaseUpgradeHistoryEntry.
type GetDatabaseUpgradeHistoryEntryResultOutput struct{ *pulumi.OutputState }

func (GetDatabaseUpgradeHistoryEntryResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabaseUpgradeHistoryEntryResult)(nil)).Elem()
}

func (o GetDatabaseUpgradeHistoryEntryResultOutput) ToGetDatabaseUpgradeHistoryEntryResultOutput() GetDatabaseUpgradeHistoryEntryResultOutput {
	return o
}

func (o GetDatabaseUpgradeHistoryEntryResultOutput) ToGetDatabaseUpgradeHistoryEntryResultOutputWithContext(ctx context.Context) GetDatabaseUpgradeHistoryEntryResultOutput {
	return o
}

// The database upgrade action.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) Action() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.Action }).(pulumi.StringOutput)
}

func (o GetDatabaseUpgradeHistoryEntryResultOutput) DatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.DatabaseId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: "-upgradeTimezone false -keepEvents"
func (o GetDatabaseUpgradeHistoryEntryResultOutput) Options() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.Options }).(pulumi.StringOutput)
}

// The source of the Oracle Database software to be used for the upgrade.
// * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
// * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) Source() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.Source }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) SourceDbHomeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.SourceDbHomeId }).(pulumi.StringOutput)
}

// Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.State }).(pulumi.StringOutput)
}

// the database software image used for upgrading database.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) TargetDatabaseSoftwareImageId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.TargetDatabaseSoftwareImageId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) TargetDbHomeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.TargetDbHomeId }).(pulumi.StringOutput)
}

// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) TargetDbVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.TargetDbVersion }).(pulumi.StringOutput)
}

// The date and time when the database upgrade ended.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) TimeEnded() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.TimeEnded }).(pulumi.StringOutput)
}

// The date and time when the database upgrade started.
func (o GetDatabaseUpgradeHistoryEntryResultOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.TimeStarted }).(pulumi.StringOutput)
}

func (o GetDatabaseUpgradeHistoryEntryResultOutput) UpgradeHistoryEntryId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabaseUpgradeHistoryEntryResult) string { return v.UpgradeHistoryEntryId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDatabaseUpgradeHistoryEntryResultOutput{})
}