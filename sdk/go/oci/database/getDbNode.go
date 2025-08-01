// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified database node.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetDbNode(ctx, &database.GetDbNodeArgs{
//				DbNodeId: dbNodeId,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDbNode(ctx *pulumi.Context, args *LookupDbNodeArgs, opts ...pulumi.InvokeOption) (*LookupDbNodeResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDbNodeResult
	err := ctx.Invoke("oci:Database/getDbNode:getDbNode", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbNode.
type LookupDbNodeArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId string `pulumi:"dbNodeId"`
}

// A collection of values returned by getDbNode.
type LookupDbNodeResult struct {
	// Additional information about the planned maintenance.
	AdditionalDetails string `pulumi:"additionalDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
	BackupIpId string `pulumi:"backupIpId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
	BackupIpv6id string `pulumi:"backupIpv6id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second backup VNIC.
	BackupVnic2id string `pulumi:"backupVnic2id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup VNIC.
	BackupVnicId string `pulumi:"backupVnicId"`
	// The number of CPU cores enabled on the Db node.
	CpuCoreCount int    `pulumi:"cpuCoreCount"`
	DbNodeId     string `pulumi:"dbNodeId"`
	// The allocated local node storage in GBs on the Db node.
	DbNodeStorageSizeInGbs int `pulumi:"dbNodeStorageSizeInGbs"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
	DbServerId string `pulumi:"dbServerId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
	DbSystemId string `pulumi:"dbSystemId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The name of the Fault Domain the instance is contained in.
	FaultDomain string `pulumi:"faultDomain"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
	HostIpId string `pulumi:"hostIpId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
	HostIpv6id string `pulumi:"hostIpv6id"`
	// The host name for the database node.
	Hostname string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database node.
	Id string `pulumi:"id"`
	// Information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The type of database node maintenance.
	MaintenanceType string `pulumi:"maintenanceType"`
	// The allocated memory in GBs on the Db node.
	MemorySizeInGbs int `pulumi:"memorySizeInGbs"`
	// The size (in GB) of the block storage volume allocation for the DB system. This attribute applies only for virtual machine DB systems.
	SoftwareStorageSizeInGb int `pulumi:"softwareStorageSizeInGb"`
	// The current state of the database node.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time that the database node was created.
	TimeCreated string `pulumi:"timeCreated"`
	// End date and time of maintenance window.
	TimeMaintenanceWindowEnd string `pulumi:"timeMaintenanceWindowEnd"`
	// Start date and time of maintenance window.
	TimeMaintenanceWindowStart string `pulumi:"timeMaintenanceWindowStart"`
	// The total number of CPU cores reserved on the Db node.
	TotalCpuCoreCount int `pulumi:"totalCpuCoreCount"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second VNIC.
	Vnic2id string `pulumi:"vnic2id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
	VnicId string `pulumi:"vnicId"`
}

func LookupDbNodeOutput(ctx *pulumi.Context, args LookupDbNodeOutputArgs, opts ...pulumi.InvokeOption) LookupDbNodeResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDbNodeResultOutput, error) {
			args := v.(LookupDbNodeArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbNode:getDbNode", args, LookupDbNodeResultOutput{}, options).(LookupDbNodeResultOutput), nil
		}).(LookupDbNodeResultOutput)
}

// A collection of arguments for invoking getDbNode.
type LookupDbNodeOutputArgs struct {
	// The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbNodeId pulumi.StringInput `pulumi:"dbNodeId"`
}

func (LookupDbNodeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbNodeArgs)(nil)).Elem()
}

// A collection of values returned by getDbNode.
type LookupDbNodeResultOutput struct{ *pulumi.OutputState }

func (LookupDbNodeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbNodeResult)(nil)).Elem()
}

func (o LookupDbNodeResultOutput) ToLookupDbNodeResultOutput() LookupDbNodeResultOutput {
	return o
}

func (o LookupDbNodeResultOutput) ToLookupDbNodeResultOutputWithContext(ctx context.Context) LookupDbNodeResultOutput {
	return o
}

// Additional information about the planned maintenance.
func (o LookupDbNodeResultOutput) AdditionalDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.AdditionalDetails }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
func (o LookupDbNodeResultOutput) BackupIpId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.BackupIpId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
func (o LookupDbNodeResultOutput) BackupIpv6id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.BackupIpv6id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second backup VNIC.
func (o LookupDbNodeResultOutput) BackupVnic2id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.BackupVnic2id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup VNIC.
func (o LookupDbNodeResultOutput) BackupVnicId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.BackupVnicId }).(pulumi.StringOutput)
}

// The number of CPU cores enabled on the Db node.
func (o LookupDbNodeResultOutput) CpuCoreCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDbNodeResult) int { return v.CpuCoreCount }).(pulumi.IntOutput)
}

func (o LookupDbNodeResultOutput) DbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.DbNodeId }).(pulumi.StringOutput)
}

// The allocated local node storage in GBs on the Db node.
func (o LookupDbNodeResultOutput) DbNodeStorageSizeInGbs() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDbNodeResult) int { return v.DbNodeStorageSizeInGbs }).(pulumi.IntOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
func (o LookupDbNodeResultOutput) DbServerId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.DbServerId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
func (o LookupDbNodeResultOutput) DbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.DbSystemId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupDbNodeResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbNodeResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The name of the Fault Domain the instance is contained in.
func (o LookupDbNodeResultOutput) FaultDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.FaultDomain }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupDbNodeResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbNodeResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
func (o LookupDbNodeResultOutput) HostIpId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.HostIpId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
func (o LookupDbNodeResultOutput) HostIpv6id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.HostIpv6id }).(pulumi.StringOutput)
}

// The host name for the database node.
func (o LookupDbNodeResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database node.
func (o LookupDbNodeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.Id }).(pulumi.StringOutput)
}

// Information about the current lifecycle state.
func (o LookupDbNodeResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The type of database node maintenance.
func (o LookupDbNodeResultOutput) MaintenanceType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.MaintenanceType }).(pulumi.StringOutput)
}

// The allocated memory in GBs on the Db node.
func (o LookupDbNodeResultOutput) MemorySizeInGbs() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDbNodeResult) int { return v.MemorySizeInGbs }).(pulumi.IntOutput)
}

// The size (in GB) of the block storage volume allocation for the DB system. This attribute applies only for virtual machine DB systems.
func (o LookupDbNodeResultOutput) SoftwareStorageSizeInGb() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDbNodeResult) int { return v.SoftwareStorageSizeInGb }).(pulumi.IntOutput)
}

// The current state of the database node.
func (o LookupDbNodeResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupDbNodeResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbNodeResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time that the database node was created.
func (o LookupDbNodeResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// End date and time of maintenance window.
func (o LookupDbNodeResultOutput) TimeMaintenanceWindowEnd() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.TimeMaintenanceWindowEnd }).(pulumi.StringOutput)
}

// Start date and time of maintenance window.
func (o LookupDbNodeResultOutput) TimeMaintenanceWindowStart() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.TimeMaintenanceWindowStart }).(pulumi.StringOutput)
}

// The total number of CPU cores reserved on the Db node.
func (o LookupDbNodeResultOutput) TotalCpuCoreCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupDbNodeResult) int { return v.TotalCpuCoreCount }).(pulumi.IntOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second VNIC.
func (o LookupDbNodeResultOutput) Vnic2id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.Vnic2id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
func (o LookupDbNodeResultOutput) VnicId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbNodeResult) string { return v.VnicId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDbNodeResultOutput{})
}
