// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Mysql Db System resource in Oracle Cloud Infrastructure MySQL Database service.
//
// Get information about the specified DB System.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Mysql.GetMysqlDbSystem(ctx, &mysql.GetMysqlDbSystemArgs{
//				DbSystemId: oci_mysql_mysql_db_system.Test_db_system.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMysqlDbSystem(ctx *pulumi.Context, args *LookupMysqlDbSystemArgs, opts ...pulumi.InvokeOption) (*LookupMysqlDbSystemResult, error) {
	var rv LookupMysqlDbSystemResult
	err := ctx.Invoke("oci:Mysql/getMysqlDbSystem:getMysqlDbSystem", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMysqlDbSystem.
type LookupMysqlDbSystemArgs struct {
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId string `pulumi:"dbSystemId"`
}

// A collection of values returned by getMysqlDbSystem.
type LookupMysqlDbSystemResult struct {
	AdminPassword string `pulumi:"adminPassword"`
	AdminUsername string `pulumi:"adminUsername"`
	// DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
	AnalyticsClusters []GetMysqlDbSystemAnalyticsCluster `pulumi:"analyticsClusters"`
	// The availability domain in which the DB System is placed.
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The Backup policy for the DB System.
	BackupPolicies []GetMysqlDbSystemBackupPolicy `pulumi:"backupPolicies"`
	// A list with a summary of all the Channels attached to the DB System.
	Channels []GetMysqlDbSystemChannel `pulumi:"channels"`
	// The OCID of the compartment the DB System belongs in.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the Configuration to be used for Instances in this DB System.
	ConfigurationId string `pulumi:"configurationId"`
	// Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
	CrashRecovery string `pulumi:"crashRecovery"`
	// The availability domain and fault domain a DB System is placed in.
	CurrentPlacements []GetMysqlDbSystemCurrentPlacement `pulumi:"currentPlacements"`
	// Initial size of the data volume in GiBs that will be created and attached.
	DataStorageSizeInGb int `pulumi:"dataStorageSizeInGb"`
	// The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
	DbSystemId string `pulumi:"dbSystemId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The Deletion policy for the DB System.
	DeletionPolicies []GetMysqlDbSystemDeletionPolicy `pulumi:"deletionPolicies"`
	// User-provided data about the DB System.
	Description string `pulumi:"description"`
	// The user-friendly name for the DB System. It does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// The network endpoints available for this DB System.
	Endpoints []GetMysqlDbSystemEndpoint `pulumi:"endpoints"`
	// The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
	FaultDomain string `pulumi:"faultDomain"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A summary of a HeatWave cluster.
	HeatWaveClusters []GetMysqlDbSystemHeatWaveCluster `pulumi:"heatWaveClusters"`
	// The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, "dbsystem-1" in FQDN "dbsystem-1.subnet123.vcn1.oraclevcn.com"). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
	HostnameLabel string `pulumi:"hostnameLabel"`
	// The OCID of the DB System.
	Id string `pulumi:"id"`
	// The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. This will be a "dotted-quad" style IPv4 address.
	IpAddress string `pulumi:"ipAddress"`
	// DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
	IsAnalyticsClusterAttached bool `pulumi:"isAnalyticsClusterAttached"`
	// If the DB System has a HeatWave Cluster attached.
	IsHeatWaveClusterAttached bool `pulumi:"isHeatWaveClusterAttached"`
	// Specifies if the DB System is highly available.
	IsHighlyAvailable bool `pulumi:"isHighlyAvailable"`
	// Additional information about the current lifecycleState.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The Maintenance Policy for the DB System.
	Maintenances []GetMysqlDbSystemMaintenance `pulumi:"maintenances"`
	// Name of the MySQL Version in use for the DB System.
	MysqlVersion string `pulumi:"mysqlVersion"`
	// Point-in-time Recovery details like earliest and latest recovery time point for the DB System.
	PointInTimeRecoveryDetails []GetMysqlDbSystemPointInTimeRecoveryDetail `pulumi:"pointInTimeRecoveryDetails"`
	// The port for primary endpoint of the DB System to listen on.
	Port int `pulumi:"port"`
	// The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
	PortX int `pulumi:"portX"`
	// The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
	ShapeName    string `pulumi:"shapeName"`
	ShutdownType string `pulumi:"shutdownType"`
	// Parameters detailing how to provision the initial data of the DB System.
	Sources []GetMysqlDbSystemSource `pulumi:"sources"`
	// The current state of the DB System.
	State string `pulumi:"state"`
	// The OCID of the subnet the DB System is associated with.
	SubnetId string `pulumi:"subnetId"`
	// The date and time the DB System was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the DB System was last updated.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupMysqlDbSystemOutput(ctx *pulumi.Context, args LookupMysqlDbSystemOutputArgs, opts ...pulumi.InvokeOption) LookupMysqlDbSystemResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupMysqlDbSystemResult, error) {
			args := v.(LookupMysqlDbSystemArgs)
			r, err := LookupMysqlDbSystem(ctx, &args, opts...)
			var s LookupMysqlDbSystemResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupMysqlDbSystemResultOutput)
}

// A collection of arguments for invoking getMysqlDbSystem.
type LookupMysqlDbSystemOutputArgs struct {
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringInput `pulumi:"dbSystemId"`
}

func (LookupMysqlDbSystemOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMysqlDbSystemArgs)(nil)).Elem()
}

// A collection of values returned by getMysqlDbSystem.
type LookupMysqlDbSystemResultOutput struct{ *pulumi.OutputState }

func (LookupMysqlDbSystemResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMysqlDbSystemResult)(nil)).Elem()
}

func (o LookupMysqlDbSystemResultOutput) ToLookupMysqlDbSystemResultOutput() LookupMysqlDbSystemResultOutput {
	return o
}

func (o LookupMysqlDbSystemResultOutput) ToLookupMysqlDbSystemResultOutputWithContext(ctx context.Context) LookupMysqlDbSystemResultOutput {
	return o
}

func (o LookupMysqlDbSystemResultOutput) AdminPassword() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.AdminPassword }).(pulumi.StringOutput)
}

func (o LookupMysqlDbSystemResultOutput) AdminUsername() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.AdminUsername }).(pulumi.StringOutput)
}

// DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
func (o LookupMysqlDbSystemResultOutput) AnalyticsClusters() GetMysqlDbSystemAnalyticsClusterArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemAnalyticsCluster { return v.AnalyticsClusters }).(GetMysqlDbSystemAnalyticsClusterArrayOutput)
}

// The availability domain in which the DB System is placed.
func (o LookupMysqlDbSystemResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The Backup policy for the DB System.
func (o LookupMysqlDbSystemResultOutput) BackupPolicies() GetMysqlDbSystemBackupPolicyArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemBackupPolicy { return v.BackupPolicies }).(GetMysqlDbSystemBackupPolicyArrayOutput)
}

// A list with a summary of all the Channels attached to the DB System.
func (o LookupMysqlDbSystemResultOutput) Channels() GetMysqlDbSystemChannelArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemChannel { return v.Channels }).(GetMysqlDbSystemChannelArrayOutput)
}

// The OCID of the compartment the DB System belongs in.
func (o LookupMysqlDbSystemResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the Configuration to be used for Instances in this DB System.
func (o LookupMysqlDbSystemResultOutput) ConfigurationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.ConfigurationId }).(pulumi.StringOutput)
}

// Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
func (o LookupMysqlDbSystemResultOutput) CrashRecovery() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.CrashRecovery }).(pulumi.StringOutput)
}

// The availability domain and fault domain a DB System is placed in.
func (o LookupMysqlDbSystemResultOutput) CurrentPlacements() GetMysqlDbSystemCurrentPlacementArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemCurrentPlacement { return v.CurrentPlacements }).(GetMysqlDbSystemCurrentPlacementArrayOutput)
}

// Initial size of the data volume in GiBs that will be created and attached.
func (o LookupMysqlDbSystemResultOutput) DataStorageSizeInGb() pulumi.IntOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) int { return v.DataStorageSizeInGb }).(pulumi.IntOutput)
}

// The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
func (o LookupMysqlDbSystemResultOutput) DbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.DbSystemId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupMysqlDbSystemResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The Deletion policy for the DB System.
func (o LookupMysqlDbSystemResultOutput) DeletionPolicies() GetMysqlDbSystemDeletionPolicyArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemDeletionPolicy { return v.DeletionPolicies }).(GetMysqlDbSystemDeletionPolicyArrayOutput)
}

// User-provided data about the DB System.
func (o LookupMysqlDbSystemResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.Description }).(pulumi.StringOutput)
}

// The user-friendly name for the DB System. It does not have to be unique.
func (o LookupMysqlDbSystemResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The network endpoints available for this DB System.
func (o LookupMysqlDbSystemResultOutput) Endpoints() GetMysqlDbSystemEndpointArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemEndpoint { return v.Endpoints }).(GetMysqlDbSystemEndpointArrayOutput)
}

// The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
func (o LookupMysqlDbSystemResultOutput) FaultDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.FaultDomain }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupMysqlDbSystemResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// A summary of a HeatWave cluster.
func (o LookupMysqlDbSystemResultOutput) HeatWaveClusters() GetMysqlDbSystemHeatWaveClusterArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemHeatWaveCluster { return v.HeatWaveClusters }).(GetMysqlDbSystemHeatWaveClusterArrayOutput)
}

// The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, "dbsystem-1" in FQDN "dbsystem-1.subnet123.vcn1.oraclevcn.com"). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
func (o LookupMysqlDbSystemResultOutput) HostnameLabel() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.HostnameLabel }).(pulumi.StringOutput)
}

// The OCID of the DB System.
func (o LookupMysqlDbSystemResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.Id }).(pulumi.StringOutput)
}

// The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. This will be a "dotted-quad" style IPv4 address.
func (o LookupMysqlDbSystemResultOutput) IpAddress() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.IpAddress }).(pulumi.StringOutput)
}

// DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
func (o LookupMysqlDbSystemResultOutput) IsAnalyticsClusterAttached() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) bool { return v.IsAnalyticsClusterAttached }).(pulumi.BoolOutput)
}

// If the DB System has a HeatWave Cluster attached.
func (o LookupMysqlDbSystemResultOutput) IsHeatWaveClusterAttached() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) bool { return v.IsHeatWaveClusterAttached }).(pulumi.BoolOutput)
}

// Specifies if the DB System is highly available.
func (o LookupMysqlDbSystemResultOutput) IsHighlyAvailable() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) bool { return v.IsHighlyAvailable }).(pulumi.BoolOutput)
}

// Additional information about the current lifecycleState.
func (o LookupMysqlDbSystemResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The Maintenance Policy for the DB System.
func (o LookupMysqlDbSystemResultOutput) Maintenances() GetMysqlDbSystemMaintenanceArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemMaintenance { return v.Maintenances }).(GetMysqlDbSystemMaintenanceArrayOutput)
}

// Name of the MySQL Version in use for the DB System.
func (o LookupMysqlDbSystemResultOutput) MysqlVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.MysqlVersion }).(pulumi.StringOutput)
}

// Point-in-time Recovery details like earliest and latest recovery time point for the DB System.
func (o LookupMysqlDbSystemResultOutput) PointInTimeRecoveryDetails() GetMysqlDbSystemPointInTimeRecoveryDetailArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemPointInTimeRecoveryDetail {
		return v.PointInTimeRecoveryDetails
	}).(GetMysqlDbSystemPointInTimeRecoveryDetailArrayOutput)
}

// The port for primary endpoint of the DB System to listen on.
func (o LookupMysqlDbSystemResultOutput) Port() pulumi.IntOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) int { return v.Port }).(pulumi.IntOutput)
}

// The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
func (o LookupMysqlDbSystemResultOutput) PortX() pulumi.IntOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) int { return v.PortX }).(pulumi.IntOutput)
}

// The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
func (o LookupMysqlDbSystemResultOutput) ShapeName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.ShapeName }).(pulumi.StringOutput)
}

func (o LookupMysqlDbSystemResultOutput) ShutdownType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.ShutdownType }).(pulumi.StringOutput)
}

// Parameters detailing how to provision the initial data of the DB System.
func (o LookupMysqlDbSystemResultOutput) Sources() GetMysqlDbSystemSourceArrayOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) []GetMysqlDbSystemSource { return v.Sources }).(GetMysqlDbSystemSourceArrayOutput)
}

// The current state of the DB System.
func (o LookupMysqlDbSystemResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.State }).(pulumi.StringOutput)
}

// The OCID of the subnet the DB System is associated with.
func (o LookupMysqlDbSystemResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// The date and time the DB System was created.
func (o LookupMysqlDbSystemResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the DB System was last updated.
func (o LookupMysqlDbSystemResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMysqlDbSystemResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMysqlDbSystemResultOutput{})
}