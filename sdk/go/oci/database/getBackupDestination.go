// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Backup Destination resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified backup destination in an Exadata Cloud@Customer system.
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
//			_, err := Database.GetBackupDestination(ctx, &database.GetBackupDestinationArgs{
//				BackupDestinationId: oci_database_backup_destination.Test_backup_destination.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupBackupDestination(ctx *pulumi.Context, args *LookupBackupDestinationArgs, opts ...pulumi.InvokeOption) (*LookupBackupDestinationResult, error) {
	var rv LookupBackupDestinationResult
	err := ctx.Invoke("oci:Database/getBackupDestination:getBackupDestination", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBackupDestination.
type LookupBackupDestinationArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
	BackupDestinationId string `pulumi:"backupDestinationId"`
}

// A collection of values returned by getBackupDestination.
type LookupBackupDestinationResult struct {
	// List of databases associated with the backup destination.
	AssociatedDatabases []GetBackupDestinationAssociatedDatabase `pulumi:"associatedDatabases"`
	BackupDestinationId string                                   `pulumi:"backupDestinationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// For a RECOVERY_APPLIANCE backup destination, the connection string for connecting to the Recovery Appliance.
	ConnectionString string `pulumi:"connectionString"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-provided name of the backup destination.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
	Id string `pulumi:"id"`
	// A descriptive text associated with the lifecycleState. Typically contains additional displayable text
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes.
	//
	// Deprecated: The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead.
	LocalMountPointPath string                                `pulumi:"localMountPointPath"`
	MountTypeDetails    []GetBackupDestinationMountTypeDetail `pulumi:"mountTypeDetails"`
	// NFS Mount type for backup destination.
	NfsMountType string `pulumi:"nfsMountType"`
	// Specifies the directory on which to mount the file system
	NfsServerExport string `pulumi:"nfsServerExport"`
	// Host names or IP addresses for NFS Auto mount.
	NfsServers []string `pulumi:"nfsServers"`
	// The current lifecycle state of the backup destination.
	State string `pulumi:"state"`
	// The date and time the backup destination was created.
	TimeCreated string `pulumi:"timeCreated"`
	// Type of the backup destination.
	Type string `pulumi:"type"`
	// For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
	VpcUsers []string `pulumi:"vpcUsers"`
}

func LookupBackupDestinationOutput(ctx *pulumi.Context, args LookupBackupDestinationOutputArgs, opts ...pulumi.InvokeOption) LookupBackupDestinationResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupBackupDestinationResult, error) {
			args := v.(LookupBackupDestinationArgs)
			r, err := LookupBackupDestination(ctx, &args, opts...)
			var s LookupBackupDestinationResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupBackupDestinationResultOutput)
}

// A collection of arguments for invoking getBackupDestination.
type LookupBackupDestinationOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
	BackupDestinationId pulumi.StringInput `pulumi:"backupDestinationId"`
}

func (LookupBackupDestinationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBackupDestinationArgs)(nil)).Elem()
}

// A collection of values returned by getBackupDestination.
type LookupBackupDestinationResultOutput struct{ *pulumi.OutputState }

func (LookupBackupDestinationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBackupDestinationResult)(nil)).Elem()
}

func (o LookupBackupDestinationResultOutput) ToLookupBackupDestinationResultOutput() LookupBackupDestinationResultOutput {
	return o
}

func (o LookupBackupDestinationResultOutput) ToLookupBackupDestinationResultOutputWithContext(ctx context.Context) LookupBackupDestinationResultOutput {
	return o
}

// List of databases associated with the backup destination.
func (o LookupBackupDestinationResultOutput) AssociatedDatabases() GetBackupDestinationAssociatedDatabaseArrayOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) []GetBackupDestinationAssociatedDatabase {
		return v.AssociatedDatabases
	}).(GetBackupDestinationAssociatedDatabaseArrayOutput)
}

func (o LookupBackupDestinationResultOutput) BackupDestinationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.BackupDestinationId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupBackupDestinationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// For a RECOVERY_APPLIANCE backup destination, the connection string for connecting to the Recovery Appliance.
func (o LookupBackupDestinationResultOutput) ConnectionString() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.ConnectionString }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupBackupDestinationResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The user-provided name of the backup destination.
func (o LookupBackupDestinationResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupBackupDestinationResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
func (o LookupBackupDestinationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.Id }).(pulumi.StringOutput)
}

// A descriptive text associated with the lifecycleState. Typically contains additional displayable text
func (o LookupBackupDestinationResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes.
//
// Deprecated: The 'local_mount_point_path' field has been deprecated. Please use 'local_mount_point_path under mount_type_details' instead.
func (o LookupBackupDestinationResultOutput) LocalMountPointPath() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.LocalMountPointPath }).(pulumi.StringOutput)
}

func (o LookupBackupDestinationResultOutput) MountTypeDetails() GetBackupDestinationMountTypeDetailArrayOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) []GetBackupDestinationMountTypeDetail { return v.MountTypeDetails }).(GetBackupDestinationMountTypeDetailArrayOutput)
}

// NFS Mount type for backup destination.
func (o LookupBackupDestinationResultOutput) NfsMountType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.NfsMountType }).(pulumi.StringOutput)
}

// Specifies the directory on which to mount the file system
func (o LookupBackupDestinationResultOutput) NfsServerExport() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.NfsServerExport }).(pulumi.StringOutput)
}

// Host names or IP addresses for NFS Auto mount.
func (o LookupBackupDestinationResultOutput) NfsServers() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) []string { return v.NfsServers }).(pulumi.StringArrayOutput)
}

// The current lifecycle state of the backup destination.
func (o LookupBackupDestinationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the backup destination was created.
func (o LookupBackupDestinationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Type of the backup destination.
func (o LookupBackupDestinationResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) string { return v.Type }).(pulumi.StringOutput)
}

// For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
func (o LookupBackupDestinationResultOutput) VpcUsers() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupBackupDestinationResult) []string { return v.VpcUsers }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupBackupDestinationResultOutput{})
}