// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Exadata Infrastructure resource in Oracle Cloud Infrastructure Database service.
//
// **Deprecated.** Use the [GetCloudExadataInfrastructure](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/GetCloudExadataInfrastructure) operation to get details of an Exadata Infrastructure resource and the [GetCloudAutonomousVmCluster](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudAutonomousVmCluster/GetCloudAutonomousVmCluster) operation to get details of an Autonomous Exadata VM cluster.
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
//			_, err := database.GetAutonomousExadataInfrastructure(ctx, &database.GetAutonomousExadataInfrastructureArgs{
//				AutonomousExadataInfrastructureId: testAutonomousExadataInfrastructureOciDatabaseAutonomousExadataInfrastructure.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAutonomousExadataInfrastructure(ctx *pulumi.Context, args *LookupAutonomousExadataInfrastructureArgs, opts ...pulumi.InvokeOption) (*LookupAutonomousExadataInfrastructureResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupAutonomousExadataInfrastructureResult
	err := ctx.Invoke("oci:Database/getAutonomousExadataInfrastructure:getAutonomousExadataInfrastructure", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousExadataInfrastructure.
type LookupAutonomousExadataInfrastructureArgs struct {
	// The Autonomous Exadata Infrastructure  [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousExadataInfrastructureId string `pulumi:"autonomousExadataInfrastructureId"`
}

// A collection of values returned by getAutonomousExadataInfrastructure.
type LookupAutonomousExadataInfrastructureResult struct {
	AutonomousExadataInfrastructureId string `pulumi:"autonomousExadataInfrastructureId"`
	// The name of the availability domain that the Autonomous Exadata Infrastructure is located in.
	//
	// Deprecated: Autonomous Exadata Infrastructure resource is now end-of-life.Please provision cloud autonomous vm cluster instead.
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	CreateAsync   bool   `pulumi:"createAsync"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the Autonomous Exadata Infrastructure.
	DisplayName string `pulumi:"displayName"`
	// The domain name for the Autonomous Exadata Infrastructure.
	Domain string `pulumi:"domain"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The host name for the Autonomous Exadata Infrastructure node.
	Hostname string `pulumi:"hostname"`
	// The OCID of the Autonomous Exadata Infrastructure.
	Id string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
	LastMaintenanceRunId string `pulumi:"lastMaintenanceRunId"`
	// The Oracle license model that applies to all databases in the Autonomous Exadata Infrastructure. The default is BRING_YOUR_OWN_LICENSE.
	LicenseModel string `pulumi:"licenseModel"`
	// Additional information about the current lifecycle state of the Autonomous Exadata Infrastructure.
	LifecycleDetails         string                                                      `pulumi:"lifecycleDetails"`
	MaintenanceWindowDetails []GetAutonomousExadataInfrastructureMaintenanceWindowDetail `pulumi:"maintenanceWindowDetails"`
	// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
	MaintenanceWindows []GetAutonomousExadataInfrastructureMaintenanceWindow `pulumi:"maintenanceWindows"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
	NextMaintenanceRunId string `pulumi:"nextMaintenanceRunId"`
	// The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the network security groups (NSGs) to which this resource belongs. Setting this to an empty list removes all resources from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
	// * A network security group (NSG) is optional for Autonomous Databases with private access. The nsgIds list can be empty.
	NsgIds []string `pulumi:"nsgIds"`
	// The FQDN of the DNS record for the SCAN IP addresses that are associated with the Autonomous Exadata Infrastructure.
	ScanDnsName string `pulumi:"scanDnsName"`
	// The shape of the Autonomous Exadata Infrastructure. The shape determines resources to allocate to the Autonomous Exadata Infrastructure (CPU cores, memory and storage).
	Shape string `pulumi:"shape"`
	// The current lifecycle state of the Autonomous Exadata Infrastructure.
	State string `pulumi:"state"`
	// The OCID of the subnet the Autonomous Exadata Infrastructure is associated with.
	SubnetId string `pulumi:"subnetId"`
	// The date and time the Autonomous Exadata Infrastructure was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The OCID of the zone the Autonomous Exadata Infrastructure is associated with.
	ZoneId string `pulumi:"zoneId"`
}

func LookupAutonomousExadataInfrastructureOutput(ctx *pulumi.Context, args LookupAutonomousExadataInfrastructureOutputArgs, opts ...pulumi.InvokeOption) LookupAutonomousExadataInfrastructureResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupAutonomousExadataInfrastructureResultOutput, error) {
			args := v.(LookupAutonomousExadataInfrastructureArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getAutonomousExadataInfrastructure:getAutonomousExadataInfrastructure", args, LookupAutonomousExadataInfrastructureResultOutput{}, options).(LookupAutonomousExadataInfrastructureResultOutput), nil
		}).(LookupAutonomousExadataInfrastructureResultOutput)
}

// A collection of arguments for invoking getAutonomousExadataInfrastructure.
type LookupAutonomousExadataInfrastructureOutputArgs struct {
	// The Autonomous Exadata Infrastructure  [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousExadataInfrastructureId pulumi.StringInput `pulumi:"autonomousExadataInfrastructureId"`
}

func (LookupAutonomousExadataInfrastructureOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousExadataInfrastructureArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousExadataInfrastructure.
type LookupAutonomousExadataInfrastructureResultOutput struct{ *pulumi.OutputState }

func (LookupAutonomousExadataInfrastructureResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousExadataInfrastructureResult)(nil)).Elem()
}

func (o LookupAutonomousExadataInfrastructureResultOutput) ToLookupAutonomousExadataInfrastructureResultOutput() LookupAutonomousExadataInfrastructureResultOutput {
	return o
}

func (o LookupAutonomousExadataInfrastructureResultOutput) ToLookupAutonomousExadataInfrastructureResultOutputWithContext(ctx context.Context) LookupAutonomousExadataInfrastructureResultOutput {
	return o
}

func (o LookupAutonomousExadataInfrastructureResultOutput) AutonomousExadataInfrastructureId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.AutonomousExadataInfrastructureId }).(pulumi.StringOutput)
}

// The name of the availability domain that the Autonomous Exadata Infrastructure is located in.
//
// Deprecated: Autonomous Exadata Infrastructure resource is now end-of-life.Please provision cloud autonomous vm cluster instead.
func (o LookupAutonomousExadataInfrastructureResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The OCID of the compartment.
func (o LookupAutonomousExadataInfrastructureResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupAutonomousExadataInfrastructureResultOutput) CreateAsync() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) bool { return v.CreateAsync }).(pulumi.BoolOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupAutonomousExadataInfrastructureResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The domain name for the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) Domain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.Domain }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupAutonomousExadataInfrastructureResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The host name for the Autonomous Exadata Infrastructure node.
func (o LookupAutonomousExadataInfrastructureResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// The OCID of the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.Id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
func (o LookupAutonomousExadataInfrastructureResultOutput) LastMaintenanceRunId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.LastMaintenanceRunId }).(pulumi.StringOutput)
}

// The Oracle license model that applies to all databases in the Autonomous Exadata Infrastructure. The default is BRING_YOUR_OWN_LICENSE.
func (o LookupAutonomousExadataInfrastructureResultOutput) LicenseModel() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.LicenseModel }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state of the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupAutonomousExadataInfrastructureResultOutput) MaintenanceWindowDetails() GetAutonomousExadataInfrastructureMaintenanceWindowDetailArrayOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) []GetAutonomousExadataInfrastructureMaintenanceWindowDetail {
		return v.MaintenanceWindowDetails
	}).(GetAutonomousExadataInfrastructureMaintenanceWindowDetailArrayOutput)
}

// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
func (o LookupAutonomousExadataInfrastructureResultOutput) MaintenanceWindows() GetAutonomousExadataInfrastructureMaintenanceWindowArrayOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) []GetAutonomousExadataInfrastructureMaintenanceWindow {
		return v.MaintenanceWindows
	}).(GetAutonomousExadataInfrastructureMaintenanceWindowArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
func (o LookupAutonomousExadataInfrastructureResultOutput) NextMaintenanceRunId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.NextMaintenanceRunId }).(pulumi.StringOutput)
}

// The list of [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the network security groups (NSGs) to which this resource belongs. Setting this to an empty list removes all resources from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
// * A network security group (NSG) is optional for Autonomous Databases with private access. The nsgIds list can be empty.
func (o LookupAutonomousExadataInfrastructureResultOutput) NsgIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) []string { return v.NsgIds }).(pulumi.StringArrayOutput)
}

// The FQDN of the DNS record for the SCAN IP addresses that are associated with the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) ScanDnsName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.ScanDnsName }).(pulumi.StringOutput)
}

// The shape of the Autonomous Exadata Infrastructure. The shape determines resources to allocate to the Autonomous Exadata Infrastructure (CPU cores, memory and storage).
func (o LookupAutonomousExadataInfrastructureResultOutput) Shape() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.Shape }).(pulumi.StringOutput)
}

// The current lifecycle state of the Autonomous Exadata Infrastructure.
func (o LookupAutonomousExadataInfrastructureResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.State }).(pulumi.StringOutput)
}

// The OCID of the subnet the Autonomous Exadata Infrastructure is associated with.
func (o LookupAutonomousExadataInfrastructureResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// The date and time the Autonomous Exadata Infrastructure was created.
func (o LookupAutonomousExadataInfrastructureResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The OCID of the zone the Autonomous Exadata Infrastructure is associated with.
func (o LookupAutonomousExadataInfrastructureResultOutput) ZoneId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousExadataInfrastructureResult) string { return v.ZoneId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAutonomousExadataInfrastructureResultOutput{})
}
