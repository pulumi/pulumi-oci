// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Mysql Backups in Oracle Cloud Infrastructure MySQL Database service.
//
// Get a list of DB System backups.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := mysql.GetMysqlBackups(ctx, &mysql.GetMysqlBackupsArgs{
//				CompartmentId: compartmentId,
//				BackupId:      pulumi.StringRef(testBackup.Id),
//				CreationType:  pulumi.StringRef(mysqlBackupCreationType),
//				DbSystemId:    pulumi.StringRef(testDbSystem.Id),
//				DisplayName:   pulumi.StringRef(mysqlBackupDisplayName),
//				SoftDelete:    pulumi.StringRef(mysqlBackupSoftDelete),
//				State:         pulumi.StringRef(mysqlBackupState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMysqlBackups(ctx *pulumi.Context, args *GetMysqlBackupsArgs, opts ...pulumi.InvokeOption) (*GetMysqlBackupsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMysqlBackupsResult
	err := ctx.Invoke("oci:Mysql/getMysqlBackups:getMysqlBackups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMysqlBackups.
type GetMysqlBackupsArgs struct {
	// Backup OCID
	BackupId *string `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// Backup creationType
	CreationType *string `pulumi:"creationType"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetMysqlBackupsFilter `pulumi:"filters"`
	// Backup Soft Delete
	SoftDelete *string `pulumi:"softDelete"`
	// Backup Lifecycle State
	State *string `pulumi:"state"`
}

// A collection of values returned by getMysqlBackups.
type GetMysqlBackupsResult struct {
	BackupId *string `pulumi:"backupId"`
	// The list of backups.
	Backups []GetMysqlBackupsBackup `pulumi:"backups"`
	// The OCID of the compartment the DB System belongs in.
	CompartmentId string `pulumi:"compartmentId"`
	// Indicates how the backup was created: manually, automatic, or by an Operator.
	CreationType *string `pulumi:"creationType"`
	// The OCID of the DB System the backup is associated with.
	DbSystemId *string `pulumi:"dbSystemId"`
	// A user-supplied display name for the backup.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetMysqlBackupsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
	SoftDelete *string `pulumi:"softDelete"`
	// The state of the backup.
	State *string `pulumi:"state"`
}

func GetMysqlBackupsOutput(ctx *pulumi.Context, args GetMysqlBackupsOutputArgs, opts ...pulumi.InvokeOption) GetMysqlBackupsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetMysqlBackupsResultOutput, error) {
			args := v.(GetMysqlBackupsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Mysql/getMysqlBackups:getMysqlBackups", args, GetMysqlBackupsResultOutput{}, options).(GetMysqlBackupsResultOutput), nil
		}).(GetMysqlBackupsResultOutput)
}

// A collection of arguments for invoking getMysqlBackups.
type GetMysqlBackupsOutputArgs struct {
	// Backup OCID
	BackupId pulumi.StringPtrInput `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Backup creationType
	CreationType pulumi.StringPtrInput `pulumi:"creationType"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringPtrInput `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName pulumi.StringPtrInput           `pulumi:"displayName"`
	Filters     GetMysqlBackupsFilterArrayInput `pulumi:"filters"`
	// Backup Soft Delete
	SoftDelete pulumi.StringPtrInput `pulumi:"softDelete"`
	// Backup Lifecycle State
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMysqlBackupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMysqlBackupsArgs)(nil)).Elem()
}

// A collection of values returned by getMysqlBackups.
type GetMysqlBackupsResultOutput struct{ *pulumi.OutputState }

func (GetMysqlBackupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMysqlBackupsResult)(nil)).Elem()
}

func (o GetMysqlBackupsResultOutput) ToGetMysqlBackupsResultOutput() GetMysqlBackupsResultOutput {
	return o
}

func (o GetMysqlBackupsResultOutput) ToGetMysqlBackupsResultOutputWithContext(ctx context.Context) GetMysqlBackupsResultOutput {
	return o
}

func (o GetMysqlBackupsResultOutput) BackupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.BackupId }).(pulumi.StringPtrOutput)
}

// The list of backups.
func (o GetMysqlBackupsResultOutput) Backups() GetMysqlBackupsBackupArrayOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) []GetMysqlBackupsBackup { return v.Backups }).(GetMysqlBackupsBackupArrayOutput)
}

// The OCID of the compartment the DB System belongs in.
func (o GetMysqlBackupsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Indicates how the backup was created: manually, automatic, or by an Operator.
func (o GetMysqlBackupsResultOutput) CreationType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.CreationType }).(pulumi.StringPtrOutput)
}

// The OCID of the DB System the backup is associated with.
func (o GetMysqlBackupsResultOutput) DbSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.DbSystemId }).(pulumi.StringPtrOutput)
}

// A user-supplied display name for the backup.
func (o GetMysqlBackupsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetMysqlBackupsResultOutput) Filters() GetMysqlBackupsFilterArrayOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) []GetMysqlBackupsFilter { return v.Filters }).(GetMysqlBackupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMysqlBackupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
func (o GetMysqlBackupsResultOutput) SoftDelete() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.SoftDelete }).(pulumi.StringPtrOutput)
}

// The state of the backup.
func (o GetMysqlBackupsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlBackupsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMysqlBackupsResultOutput{})
}
