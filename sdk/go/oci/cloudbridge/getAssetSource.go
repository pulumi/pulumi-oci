// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudbridge

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Asset Source resource in Oracle Cloud Infrastructure Cloud Bridge service.
//
// Gets the asset source by ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/CloudBridge"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := CloudBridge.GetAssetSource(ctx, &cloudbridge.GetAssetSourceArgs{
//				AssetSourceId: oci_cloud_bridge_asset_source.Test_asset_source.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAssetSource(ctx *pulumi.Context, args *LookupAssetSourceArgs, opts ...pulumi.InvokeOption) (*LookupAssetSourceResult, error) {
	var rv LookupAssetSourceResult
	err := ctx.Invoke("oci:CloudBridge/getAssetSource:getAssetSource", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAssetSource.
type LookupAssetSourceArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
	AssetSourceId string `pulumi:"assetSourceId"`
}

// A collection of values returned by getAssetSource.
type LookupAssetSourceResult struct {
	// Flag indicating whether historical metrics are collected for assets, originating from this asset source.
	AreHistoricalMetricsCollected bool `pulumi:"areHistoricalMetricsCollected"`
	// Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
	AreRealtimeMetricsCollected bool   `pulumi:"areRealtimeMetricsCollected"`
	AssetSourceId               string `pulumi:"assetSourceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
	AssetsCompartmentId string `pulumi:"assetsCompartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the resource.
	CompartmentId string `pulumi:"compartmentId"`
	// The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Credentials for an asset source.
	DiscoveryCredentials []GetAssetSourceDiscoveryCredential `pulumi:"discoveryCredentials"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
	DiscoveryScheduleId string `pulumi:"discoveryScheduleId"`
	// A user-friendly name for the asset source. Does not have to be unique, and it's mutable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
	EnvironmentId string `pulumi:"environmentId"`
	// The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	Id string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the inventory that will contain created assets.
	InventoryId string `pulumi:"inventoryId"`
	// The detailed state of the asset source.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Credentials for an asset source.
	ReplicationCredentials []GetAssetSourceReplicationCredential `pulumi:"replicationCredentials"`
	// The current state of the asset source.
	State string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time when the asset source was created in the RFC3339 format.
	TimeCreated string `pulumi:"timeCreated"`
	// The point in time that the asset source was last updated in the RFC3339 format.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The type of asset source. Indicates external origin of the assets that are read by assigning this asset source.
	Type string `pulumi:"type"`
	// Endpoint for VMware asset discovery and replication in the form of ```https://<host>:<port>/sdk```
	VcenterEndpoint string `pulumi:"vcenterEndpoint"`
}

func LookupAssetSourceOutput(ctx *pulumi.Context, args LookupAssetSourceOutputArgs, opts ...pulumi.InvokeOption) LookupAssetSourceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupAssetSourceResult, error) {
			args := v.(LookupAssetSourceArgs)
			r, err := LookupAssetSource(ctx, &args, opts...)
			var s LookupAssetSourceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupAssetSourceResultOutput)
}

// A collection of arguments for invoking getAssetSource.
type LookupAssetSourceOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the asset source.
	AssetSourceId pulumi.StringInput `pulumi:"assetSourceId"`
}

func (LookupAssetSourceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAssetSourceArgs)(nil)).Elem()
}

// A collection of values returned by getAssetSource.
type LookupAssetSourceResultOutput struct{ *pulumi.OutputState }

func (LookupAssetSourceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAssetSourceResult)(nil)).Elem()
}

func (o LookupAssetSourceResultOutput) ToLookupAssetSourceResultOutput() LookupAssetSourceResultOutput {
	return o
}

func (o LookupAssetSourceResultOutput) ToLookupAssetSourceResultOutputWithContext(ctx context.Context) LookupAssetSourceResultOutput {
	return o
}

// Flag indicating whether historical metrics are collected for assets, originating from this asset source.
func (o LookupAssetSourceResultOutput) AreHistoricalMetricsCollected() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) bool { return v.AreHistoricalMetricsCollected }).(pulumi.BoolOutput)
}

// Flag indicating whether real-time metrics are collected for assets, originating from this asset source.
func (o LookupAssetSourceResultOutput) AreRealtimeMetricsCollected() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) bool { return v.AreRealtimeMetricsCollected }).(pulumi.BoolOutput)
}

func (o LookupAssetSourceResultOutput) AssetSourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.AssetSourceId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that is going to be used to create assets.
func (o LookupAssetSourceResultOutput) AssetsCompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.AssetsCompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the resource.
func (o LookupAssetSourceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupAssetSourceResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Credentials for an asset source.
func (o LookupAssetSourceResultOutput) DiscoveryCredentials() GetAssetSourceDiscoveryCredentialArrayOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) []GetAssetSourceDiscoveryCredential { return v.DiscoveryCredentials }).(GetAssetSourceDiscoveryCredentialArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an attached discovery schedule.
func (o LookupAssetSourceResultOutput) DiscoveryScheduleId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.DiscoveryScheduleId }).(pulumi.StringOutput)
}

// A user-friendly name for the asset source. Does not have to be unique, and it's mutable. Avoid entering confidential information.
func (o LookupAssetSourceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the environment.
func (o LookupAssetSourceResultOutput) EnvironmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.EnvironmentId }).(pulumi.StringOutput)
}

// The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupAssetSourceResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
func (o LookupAssetSourceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.Id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the inventory that will contain created assets.
func (o LookupAssetSourceResultOutput) InventoryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.InventoryId }).(pulumi.StringOutput)
}

// The detailed state of the asset source.
func (o LookupAssetSourceResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Credentials for an asset source.
func (o LookupAssetSourceResultOutput) ReplicationCredentials() GetAssetSourceReplicationCredentialArrayOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) []GetAssetSourceReplicationCredential { return v.ReplicationCredentials }).(GetAssetSourceReplicationCredentialArrayOutput)
}

// The current state of the asset source.
func (o LookupAssetSourceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o LookupAssetSourceResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time when the asset source was created in the RFC3339 format.
func (o LookupAssetSourceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The point in time that the asset source was last updated in the RFC3339 format.
func (o LookupAssetSourceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The type of asset source. Indicates external origin of the assets that are read by assigning this asset source.
func (o LookupAssetSourceResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.Type }).(pulumi.StringOutput)
}

// Endpoint for VMware asset discovery and replication in the form of ```https://<host>:<port>/sdk```
func (o LookupAssetSourceResultOutput) VcenterEndpoint() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAssetSourceResult) string { return v.VcenterEndpoint }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAssetSourceResultOutput{})
}