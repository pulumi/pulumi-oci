// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Management Station resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Returns information about the specified management station.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/osmanagementhub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagementhub.GetManagementStation(ctx, &osmanagementhub.GetManagementStationArgs{
//				ManagementStationId: testManagementStationOciOsManagementHubManagementStation.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagementStation(ctx *pulumi.Context, args *LookupManagementStationArgs, opts ...pulumi.InvokeOption) (*LookupManagementStationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagementStationResult
	err := ctx.Invoke("oci:OsManagementHub/getManagementStation:getManagementStation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementStation.
type LookupManagementStationArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
	ManagementStationId string `pulumi:"managementStationId"`
}

// A collection of values returned by getManagementStation.
type LookupManagementStationResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the management station.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Explanation of the health status.
	Description string `pulumi:"description"`
	// User-friendly name for the management station.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Overall health information of the management station.
	Healths []GetManagementStationHealth `pulumi:"healths"`
	// Hostname of the management station.
	Hostname string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
	Id string `pulumi:"id"`
	// When enabled, the station setup script automatically runs to configure the firewall and SELinux settings on the station.
	IsAutoConfigEnabled bool `pulumi:"isAutoConfigEnabled"`
	// The location of the instance that is acting as the management station.
	Location string `pulumi:"location"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance that is acting as the management station.
	ManagedInstanceId   string `pulumi:"managedInstanceId"`
	ManagementStationId string `pulumi:"managementStationId"`
	// A decimal number representing the amount of mirror capacity used by the sync.
	MirrorCapacity int `pulumi:"mirrorCapacity"`
	// The total number of all packages within the mirrored software sources.
	MirrorPackageCount int `pulumi:"mirrorPackageCount"`
	// The total size of all software source mirrors in bytes.
	MirrorSize string `pulumi:"mirrorSize"`
	// Amount of available mirror storage in bytes.
	MirrorStorageAvailableSize string `pulumi:"mirrorStorageAvailableSize"`
	// Total mirror storage size in bytes.
	MirrorStorageSize string `pulumi:"mirrorStorageSize"`
	// Status summary of the mirror sync.
	MirrorSyncStatuses []GetManagementStationMirrorSyncStatus `pulumi:"mirrorSyncStatuses"`
	// The total number of unique packages within the mirrored software sources on the station. Each package is counted only once, regardless of how many versions it has.
	MirrorUniquePackageCount int `pulumi:"mirrorUniquePackageCount"`
	// Mirror information used for the management station configuration.
	Mirrors []GetManagementStationMirror `pulumi:"mirrors"`
	// A decimal number representing the progress of the current mirror sync.
	OverallPercentage int `pulumi:"overallPercentage"`
	// Current state of the mirror sync for the management station.
	OverallState string `pulumi:"overallState"`
	// A list of other management stations that are behind the same load balancer within a high availability configuration. Stations are identified as peers if they have the same hostname and compartment.
	PeerManagementStations []GetManagementStationPeerManagementStation `pulumi:"peerManagementStations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile used for the management station.
	ProfileId string `pulumi:"profileId"`
	// Proxy information used for the management station configuration.
	Proxies        []GetManagementStationProxy `pulumi:"proxies"`
	RefreshTrigger int                         `pulumi:"refreshTrigger"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the scheduled job for the mirror sync.
	ScheduledJobId string `pulumi:"scheduledJobId"`
	// The current state of the management station.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The number of software sources that the station is mirroring.
	TotalMirrors int `pulumi:"totalMirrors"`
}

func LookupManagementStationOutput(ctx *pulumi.Context, args LookupManagementStationOutputArgs, opts ...pulumi.InvokeOption) LookupManagementStationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupManagementStationResultOutput, error) {
			args := v.(LookupManagementStationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OsManagementHub/getManagementStation:getManagementStation", args, LookupManagementStationResultOutput{}, options).(LookupManagementStationResultOutput), nil
		}).(LookupManagementStationResultOutput)
}

// A collection of arguments for invoking getManagementStation.
type LookupManagementStationOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
	ManagementStationId pulumi.StringInput `pulumi:"managementStationId"`
}

func (LookupManagementStationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementStationArgs)(nil)).Elem()
}

// A collection of values returned by getManagementStation.
type LookupManagementStationResultOutput struct{ *pulumi.OutputState }

func (LookupManagementStationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagementStationResult)(nil)).Elem()
}

func (o LookupManagementStationResultOutput) ToLookupManagementStationResultOutput() LookupManagementStationResultOutput {
	return o
}

func (o LookupManagementStationResultOutput) ToLookupManagementStationResultOutputWithContext(ctx context.Context) LookupManagementStationResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the management station.
func (o LookupManagementStationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupManagementStationResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Explanation of the health status.
func (o LookupManagementStationResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Description }).(pulumi.StringOutput)
}

// User-friendly name for the management station.
func (o LookupManagementStationResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupManagementStationResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Overall health information of the management station.
func (o LookupManagementStationResultOutput) Healths() GetManagementStationHealthArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationHealth { return v.Healths }).(GetManagementStationHealthArrayOutput)
}

// Hostname of the management station.
func (o LookupManagementStationResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
func (o LookupManagementStationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Id }).(pulumi.StringOutput)
}

// When enabled, the station setup script automatically runs to configure the firewall and SELinux settings on the station.
func (o LookupManagementStationResultOutput) IsAutoConfigEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupManagementStationResult) bool { return v.IsAutoConfigEnabled }).(pulumi.BoolOutput)
}

// The location of the instance that is acting as the management station.
func (o LookupManagementStationResultOutput) Location() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.Location }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance that is acting as the management station.
func (o LookupManagementStationResultOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

func (o LookupManagementStationResultOutput) ManagementStationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ManagementStationId }).(pulumi.StringOutput)
}

// A decimal number representing the amount of mirror capacity used by the sync.
func (o LookupManagementStationResultOutput) MirrorCapacity() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.MirrorCapacity }).(pulumi.IntOutput)
}

// The total number of all packages within the mirrored software sources.
func (o LookupManagementStationResultOutput) MirrorPackageCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.MirrorPackageCount }).(pulumi.IntOutput)
}

// The total size of all software source mirrors in bytes.
func (o LookupManagementStationResultOutput) MirrorSize() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.MirrorSize }).(pulumi.StringOutput)
}

// Amount of available mirror storage in bytes.
func (o LookupManagementStationResultOutput) MirrorStorageAvailableSize() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.MirrorStorageAvailableSize }).(pulumi.StringOutput)
}

// Total mirror storage size in bytes.
func (o LookupManagementStationResultOutput) MirrorStorageSize() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.MirrorStorageSize }).(pulumi.StringOutput)
}

// Status summary of the mirror sync.
func (o LookupManagementStationResultOutput) MirrorSyncStatuses() GetManagementStationMirrorSyncStatusArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationMirrorSyncStatus {
		return v.MirrorSyncStatuses
	}).(GetManagementStationMirrorSyncStatusArrayOutput)
}

// The total number of unique packages within the mirrored software sources on the station. Each package is counted only once, regardless of how many versions it has.
func (o LookupManagementStationResultOutput) MirrorUniquePackageCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.MirrorUniquePackageCount }).(pulumi.IntOutput)
}

// Mirror information used for the management station configuration.
func (o LookupManagementStationResultOutput) Mirrors() GetManagementStationMirrorArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationMirror { return v.Mirrors }).(GetManagementStationMirrorArrayOutput)
}

// A decimal number representing the progress of the current mirror sync.
func (o LookupManagementStationResultOutput) OverallPercentage() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.OverallPercentage }).(pulumi.IntOutput)
}

// Current state of the mirror sync for the management station.
func (o LookupManagementStationResultOutput) OverallState() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.OverallState }).(pulumi.StringOutput)
}

// A list of other management stations that are behind the same load balancer within a high availability configuration. Stations are identified as peers if they have the same hostname and compartment.
func (o LookupManagementStationResultOutput) PeerManagementStations() GetManagementStationPeerManagementStationArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationPeerManagementStation {
		return v.PeerManagementStations
	}).(GetManagementStationPeerManagementStationArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile used for the management station.
func (o LookupManagementStationResultOutput) ProfileId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ProfileId }).(pulumi.StringOutput)
}

// Proxy information used for the management station configuration.
func (o LookupManagementStationResultOutput) Proxies() GetManagementStationProxyArrayOutput {
	return o.ApplyT(func(v LookupManagementStationResult) []GetManagementStationProxy { return v.Proxies }).(GetManagementStationProxyArrayOutput)
}

func (o LookupManagementStationResultOutput) RefreshTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.RefreshTrigger }).(pulumi.IntOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the scheduled job for the mirror sync.
func (o LookupManagementStationResultOutput) ScheduledJobId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.ScheduledJobId }).(pulumi.StringOutput)
}

// The current state of the management station.
func (o LookupManagementStationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagementStationResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupManagementStationResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagementStationResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The number of software sources that the station is mirroring.
func (o LookupManagementStationResultOutput) TotalMirrors() pulumi.IntOutput {
	return o.ApplyT(func(v LookupManagementStationResult) int { return v.TotalMirrors }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagementStationResultOutput{})
}
