// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Autonomous Database Backups in Oracle Cloud Infrastructure Database service.
//
// Gets a list of Autonomous Database backups based on either the `autonomousDatabaseId` or `compartmentId` specified as a query parameter.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Database.GetAutonomousDatabaseBackups(ctx, &database.GetAutonomousDatabaseBackupsArgs{
// 			AutonomousDatabaseId: pulumi.StringRef(oci_database_autonomous_database.Test_autonomous_database.Id),
// 			CompartmentId:        pulumi.StringRef(_var.Compartment_id),
// 			DisplayName:          pulumi.StringRef(_var.Autonomous_database_backup_display_name),
// 			State:                pulumi.StringRef(_var.Autonomous_database_backup_state),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetAutonomousDatabaseBackups(ctx *pulumi.Context, args *GetAutonomousDatabaseBackupsArgs, opts ...pulumi.InvokeOption) (*GetAutonomousDatabaseBackupsResult, error) {
	var rv GetAutonomousDatabaseBackupsResult
	err := ctx.Invoke("oci:Database/getAutonomousDatabaseBackups:getAutonomousDatabaseBackups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabaseBackups.
type GetAutonomousDatabaseBackupsArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId *string `pulumi:"autonomousDatabaseId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetAutonomousDatabaseBackupsFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAutonomousDatabaseBackups.
type GetAutonomousDatabaseBackupsResult struct {
	// The list of autonomous_database_backups.
	AutonomousDatabaseBackups []GetAutonomousDatabaseBackupsAutonomousDatabaseBackup `pulumi:"autonomousDatabaseBackups"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database.
	AutonomousDatabaseId *string `pulumi:"autonomousDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The user-friendly name for the backup. The name does not have to be unique.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetAutonomousDatabaseBackupsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the backup.
	State *string `pulumi:"state"`
}

func GetAutonomousDatabaseBackupsOutput(ctx *pulumi.Context, args GetAutonomousDatabaseBackupsOutputArgs, opts ...pulumi.InvokeOption) GetAutonomousDatabaseBackupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAutonomousDatabaseBackupsResult, error) {
			args := v.(GetAutonomousDatabaseBackupsArgs)
			r, err := GetAutonomousDatabaseBackups(ctx, &args, opts...)
			var s GetAutonomousDatabaseBackupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAutonomousDatabaseBackupsResultOutput)
}

// A collection of arguments for invoking getAutonomousDatabaseBackups.
type GetAutonomousDatabaseBackupsOutputArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId pulumi.StringPtrInput `pulumi:"autonomousDatabaseId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                        `pulumi:"displayName"`
	Filters     GetAutonomousDatabaseBackupsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAutonomousDatabaseBackupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabaseBackupsArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousDatabaseBackups.
type GetAutonomousDatabaseBackupsResultOutput struct{ *pulumi.OutputState }

func (GetAutonomousDatabaseBackupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabaseBackupsResult)(nil)).Elem()
}

func (o GetAutonomousDatabaseBackupsResultOutput) ToGetAutonomousDatabaseBackupsResultOutput() GetAutonomousDatabaseBackupsResultOutput {
	return o
}

func (o GetAutonomousDatabaseBackupsResultOutput) ToGetAutonomousDatabaseBackupsResultOutputWithContext(ctx context.Context) GetAutonomousDatabaseBackupsResultOutput {
	return o
}

// The list of autonomous_database_backups.
func (o GetAutonomousDatabaseBackupsResultOutput) AutonomousDatabaseBackups() GetAutonomousDatabaseBackupsAutonomousDatabaseBackupArrayOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) []GetAutonomousDatabaseBackupsAutonomousDatabaseBackup {
		return v.AutonomousDatabaseBackups
	}).(GetAutonomousDatabaseBackupsAutonomousDatabaseBackupArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database.
func (o GetAutonomousDatabaseBackupsResultOutput) AutonomousDatabaseId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) *string { return v.AutonomousDatabaseId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetAutonomousDatabaseBackupsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The user-friendly name for the backup. The name does not have to be unique.
func (o GetAutonomousDatabaseBackupsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAutonomousDatabaseBackupsResultOutput) Filters() GetAutonomousDatabaseBackupsFilterArrayOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) []GetAutonomousDatabaseBackupsFilter { return v.Filters }).(GetAutonomousDatabaseBackupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAutonomousDatabaseBackupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the backup.
func (o GetAutonomousDatabaseBackupsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseBackupsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAutonomousDatabaseBackupsResultOutput{})
}
