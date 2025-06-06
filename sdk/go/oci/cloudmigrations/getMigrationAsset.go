// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudmigrations

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Migration Asset resource in Oracle Cloud Infrastructure Cloud Migrations service.
//
// Gets a migration asset by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudmigrations"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudmigrations.GetMigrationAsset(ctx, &cloudmigrations.GetMigrationAssetArgs{
//				MigrationAssetId: testMigrationAssetOciCloudMigrationsMigrationAsset.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMigrationAsset(ctx *pulumi.Context, args *LookupMigrationAssetArgs, opts ...pulumi.InvokeOption) (*LookupMigrationAssetResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupMigrationAssetResult
	err := ctx.Invoke("oci:CloudMigrations/getMigrationAsset:getMigrationAsset", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMigrationAsset.
type LookupMigrationAssetArgs struct {
	// Unique migration asset identifier
	MigrationAssetId string `pulumi:"migrationAssetId"`
}

// A collection of values returned by getMigrationAsset.
type LookupMigrationAssetResult struct {
	// Availability domain
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// List of migration assets that depend on the asset.
	DependedOnBies []string `pulumi:"dependedOnBies"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Asset ID generated by mirgration service. It is used in the mirgration service pipeline.
	Id               string `pulumi:"id"`
	InventoryAssetId string `pulumi:"inventoryAssetId"`
	// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails         string   `pulumi:"lifecycleDetails"`
	MigrationAssetDependsOns []string `pulumi:"migrationAssetDependsOns"`
	MigrationAssetId         string   `pulumi:"migrationAssetId"`
	// OCID of the associated migration.
	MigrationId string `pulumi:"migrationId"`
	// List of notifications
	Notifications []string `pulumi:"notifications"`
	// The parent snapshot of the migration asset to be used by the replication task.
	ParentSnapshot string `pulumi:"parentSnapshot"`
	// Replication compartment identifier
	ReplicationCompartmentId string `pulumi:"replicationCompartmentId"`
	// Replication schedule identifier
	ReplicationScheduleId string `pulumi:"replicationScheduleId"`
	// Name of snapshot bucket
	SnapShotBucketName string `pulumi:"snapShotBucketName"`
	// Key-value pair representing disks ID mapped to the OCIDs of replicated or hydration server volume snapshots. Example: `{"bar-key": "value"}`
	Snapshots map[string]string `pulumi:"snapshots"`
	// OCID that is referenced to an asset for an inventory.
	SourceAssetId string `pulumi:"sourceAssetId"`
	// The current state of the migration asset.
	State string `pulumi:"state"`
	// Tenancy identifier
	TenancyId string `pulumi:"tenancyId"`
	// The time when the migration asset was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the migration asset was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The type of asset referenced for inventory.
	Type string `pulumi:"type"`
}

func LookupMigrationAssetOutput(ctx *pulumi.Context, args LookupMigrationAssetOutputArgs, opts ...pulumi.InvokeOption) LookupMigrationAssetResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupMigrationAssetResultOutput, error) {
			args := v.(LookupMigrationAssetArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CloudMigrations/getMigrationAsset:getMigrationAsset", args, LookupMigrationAssetResultOutput{}, options).(LookupMigrationAssetResultOutput), nil
		}).(LookupMigrationAssetResultOutput)
}

// A collection of arguments for invoking getMigrationAsset.
type LookupMigrationAssetOutputArgs struct {
	// Unique migration asset identifier
	MigrationAssetId pulumi.StringInput `pulumi:"migrationAssetId"`
}

func (LookupMigrationAssetOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMigrationAssetArgs)(nil)).Elem()
}

// A collection of values returned by getMigrationAsset.
type LookupMigrationAssetResultOutput struct{ *pulumi.OutputState }

func (LookupMigrationAssetResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMigrationAssetResult)(nil)).Elem()
}

func (o LookupMigrationAssetResultOutput) ToLookupMigrationAssetResultOutput() LookupMigrationAssetResultOutput {
	return o
}

func (o LookupMigrationAssetResultOutput) ToLookupMigrationAssetResultOutputWithContext(ctx context.Context) LookupMigrationAssetResultOutput {
	return o
}

// Availability domain
func (o LookupMigrationAssetResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// Compartment Identifier
func (o LookupMigrationAssetResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// List of migration assets that depend on the asset.
func (o LookupMigrationAssetResultOutput) DependedOnBies() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) []string { return v.DependedOnBies }).(pulumi.StringArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupMigrationAssetResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Asset ID generated by mirgration service. It is used in the mirgration service pipeline.
func (o LookupMigrationAssetResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupMigrationAssetResultOutput) InventoryAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.InventoryAssetId }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
func (o LookupMigrationAssetResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupMigrationAssetResultOutput) MigrationAssetDependsOns() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) []string { return v.MigrationAssetDependsOns }).(pulumi.StringArrayOutput)
}

func (o LookupMigrationAssetResultOutput) MigrationAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.MigrationAssetId }).(pulumi.StringOutput)
}

// OCID of the associated migration.
func (o LookupMigrationAssetResultOutput) MigrationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.MigrationId }).(pulumi.StringOutput)
}

// List of notifications
func (o LookupMigrationAssetResultOutput) Notifications() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) []string { return v.Notifications }).(pulumi.StringArrayOutput)
}

// The parent snapshot of the migration asset to be used by the replication task.
func (o LookupMigrationAssetResultOutput) ParentSnapshot() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.ParentSnapshot }).(pulumi.StringOutput)
}

// Replication compartment identifier
func (o LookupMigrationAssetResultOutput) ReplicationCompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.ReplicationCompartmentId }).(pulumi.StringOutput)
}

// Replication schedule identifier
func (o LookupMigrationAssetResultOutput) ReplicationScheduleId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.ReplicationScheduleId }).(pulumi.StringOutput)
}

// Name of snapshot bucket
func (o LookupMigrationAssetResultOutput) SnapShotBucketName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.SnapShotBucketName }).(pulumi.StringOutput)
}

// Key-value pair representing disks ID mapped to the OCIDs of replicated or hydration server volume snapshots. Example: `{"bar-key": "value"}`
func (o LookupMigrationAssetResultOutput) Snapshots() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) map[string]string { return v.Snapshots }).(pulumi.StringMapOutput)
}

// OCID that is referenced to an asset for an inventory.
func (o LookupMigrationAssetResultOutput) SourceAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.SourceAssetId }).(pulumi.StringOutput)
}

// The current state of the migration asset.
func (o LookupMigrationAssetResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.State }).(pulumi.StringOutput)
}

// Tenancy identifier
func (o LookupMigrationAssetResultOutput) TenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.TenancyId }).(pulumi.StringOutput)
}

// The time when the migration asset was created. An RFC3339 formatted datetime string.
func (o LookupMigrationAssetResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the migration asset was updated. An RFC3339 formatted datetime string.
func (o LookupMigrationAssetResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The type of asset referenced for inventory.
func (o LookupMigrationAssetResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMigrationAssetResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMigrationAssetResultOutput{})
}
