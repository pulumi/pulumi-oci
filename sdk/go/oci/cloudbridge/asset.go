// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudbridge

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Asset resource in Oracle Cloud Infrastructure Cloud Bridge service.
//
// Creates an asset.
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
//			_, err := CloudBridge.NewAsset(ctx, "testAsset", &CloudBridge.AssetArgs{
//				AssetType:        pulumi.Any(_var.Asset_asset_type),
//				CompartmentId:    pulumi.Any(_var.Compartment_id),
//				ExternalAssetKey: pulumi.Any(_var.Asset_external_asset_key),
//				InventoryId:      pulumi.Any(oci_cloud_bridge_inventory.Test_inventory.Id),
//				SourceKey:        pulumi.Any(_var.Asset_source_key),
//				AssetSourceIds:   pulumi.Any(_var.Asset_asset_source_ids),
//				Compute: &cloudbridge.AssetComputeArgs{
//					ConnectedNetworks: pulumi.Any(_var.Asset_compute_connected_networks),
//					CoresCount:        pulumi.Any(_var.Asset_compute_cores_count),
//					CpuModel:          pulumi.Any(_var.Asset_compute_cpu_model),
//					Description:       pulumi.Any(_var.Asset_compute_description),
//					Disks: cloudbridge.AssetComputeDiskArray{
//						&cloudbridge.AssetComputeDiskArgs{
//							BootOrder:      pulumi.Any(_var.Asset_compute_disks_boot_order),
//							Location:       pulumi.Any(_var.Asset_compute_disks_location),
//							Name:           pulumi.Any(_var.Asset_compute_disks_name),
//							PersistentMode: pulumi.Any(_var.Asset_compute_disks_persistent_mode),
//							SizeInMbs:      pulumi.Any(_var.Asset_compute_disks_size_in_mbs),
//							Uuid:           pulumi.Any(_var.Asset_compute_disks_uuid),
//							UuidLun:        pulumi.Any(_var.Asset_compute_disks_uuid_lun),
//						},
//					},
//					DisksCount: pulumi.Any(_var.Asset_compute_disks_count),
//					DnsName:    pulumi.Any(_var.Asset_compute_dns_name),
//					Firmware:   pulumi.Any(_var.Asset_compute_firmware),
//					GpuDevices: cloudbridge.AssetComputeGpuDeviceArray{
//						&cloudbridge.AssetComputeGpuDeviceArgs{
//							CoresCount:   pulumi.Any(_var.Asset_compute_gpu_devices_cores_count),
//							Description:  pulumi.Any(_var.Asset_compute_gpu_devices_description),
//							Manufacturer: pulumi.Any(_var.Asset_compute_gpu_devices_manufacturer),
//							MemoryInMbs:  pulumi.Any(_var.Asset_compute_gpu_devices_memory_in_mbs),
//							Name:         pulumi.Any(_var.Asset_compute_gpu_devices_name),
//						},
//					},
//					GpuDevicesCount:    pulumi.Any(_var.Asset_compute_gpu_devices_count),
//					GuestState:         pulumi.Any(_var.Asset_compute_guest_state),
//					HardwareVersion:    pulumi.Any(_var.Asset_compute_hardware_version),
//					HostName:           pulumi.Any(_var.Asset_compute_host_name),
//					IsPmemEnabled:      pulumi.Any(_var.Asset_compute_is_pmem_enabled),
//					IsTpmEnabled:       pulumi.Any(_var.Asset_compute_is_tpm_enabled),
//					LatencySensitivity: pulumi.Any(_var.Asset_compute_latency_sensitivity),
//					MemoryInMbs:        pulumi.Any(_var.Asset_compute_memory_in_mbs),
//					Nics: cloudbridge.AssetComputeNicArray{
//						&cloudbridge.AssetComputeNicArgs{
//							IpAddresses:    pulumi.Any(_var.Asset_compute_nics_ip_addresses),
//							Label:          pulumi.Any(_var.Asset_compute_nics_label),
//							MacAddress:     pulumi.Any(_var.Asset_compute_nics_mac_address),
//							MacAddressType: pulumi.Any(_var.Asset_compute_nics_mac_address_type),
//							NetworkName:    pulumi.Any(_var.Asset_compute_nics_network_name),
//							SwitchName:     pulumi.Any(_var.Asset_compute_nics_switch_name),
//						},
//					},
//					NicsCount: pulumi.Any(_var.Asset_compute_nics_count),
//					NvdimmController: &cloudbridge.AssetComputeNvdimmControllerArgs{
//						BusNumber: pulumi.Any(_var.Asset_compute_nvdimm_controller_bus_number),
//						Label:     pulumi.Any(_var.Asset_compute_nvdimm_controller_label),
//					},
//					Nvdimms: cloudbridge.AssetComputeNvdimmArray{
//						&cloudbridge.AssetComputeNvdimmArgs{
//							ControllerKey: pulumi.Any(_var.Asset_compute_nvdimms_controller_key),
//							Label:         pulumi.Any(_var.Asset_compute_nvdimms_label),
//							UnitNumber:    pulumi.Any(_var.Asset_compute_nvdimms_unit_number),
//						},
//					},
//					OperatingSystem:        pulumi.Any(_var.Asset_compute_operating_system),
//					OperatingSystemVersion: pulumi.Any(_var.Asset_compute_operating_system_version),
//					PmemInMbs:              pulumi.Any(_var.Asset_compute_pmem_in_mbs),
//					PowerState:             pulumi.Any(_var.Asset_compute_power_state),
//					PrimaryIp:              pulumi.Any(_var.Asset_compute_primary_ip),
//					ScsiController: &cloudbridge.AssetComputeScsiControllerArgs{
//						Label:      pulumi.Any(_var.Asset_compute_scsi_controller_label),
//						SharedBus:  pulumi.Any(_var.Asset_compute_scsi_controller_shared_bus),
//						UnitNumber: pulumi.Any(_var.Asset_compute_scsi_controller_unit_number),
//					},
//					StorageProvisionedInMbs: pulumi.Any(_var.Asset_compute_storage_provisioned_in_mbs),
//					ThreadsPerCoreCount:     pulumi.Any(_var.Asset_compute_threads_per_core_count),
//				},
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Asset_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				Vm: &cloudbridge.AssetVmArgs{
//					HypervisorHost:    pulumi.Any(_var.Asset_vm_hypervisor_host),
//					HypervisorVendor:  pulumi.Any(_var.Asset_vm_hypervisor_vendor),
//					HypervisorVersion: pulumi.Any(_var.Asset_vm_hypervisor_version),
//				},
//				VmwareVcenter: &cloudbridge.AssetVmwareVcenterArgs{
//					DataCenter:     pulumi.Any(_var.Asset_vmware_vcenter_data_center),
//					VcenterKey:     pulumi.Any(_var.Asset_vmware_vcenter_vcenter_key),
//					VcenterVersion: pulumi.Any(_var.Asset_vmware_vcenter_vcenter_version),
//				},
//				VmwareVm: &cloudbridge.AssetVmwareVmArgs{
//					Cluster:        pulumi.Any(_var.Asset_vmware_vm_cluster),
//					CustomerFields: pulumi.Any(_var.Asset_vmware_vm_customer_fields),
//					CustomerTags: cloudbridge.AssetVmwareVmCustomerTagArray{
//						&cloudbridge.AssetVmwareVmCustomerTagArgs{
//							Description: pulumi.Any(_var.Asset_vmware_vm_customer_tags_description),
//							Name:        pulumi.Any(_var.Asset_vmware_vm_customer_tags_name),
//						},
//					},
//					FaultToleranceBandwidth:        pulumi.Any(_var.Asset_vmware_vm_fault_tolerance_bandwidth),
//					FaultToleranceSecondaryLatency: pulumi.Any(_var.Asset_vmware_vm_fault_tolerance_secondary_latency),
//					FaultToleranceState:            pulumi.Any(_var.Asset_vmware_vm_fault_tolerance_state),
//					InstanceUuid:                   pulumi.Any(_var.Asset_vmware_vm_instance_uuid),
//					IsDisksCbtEnabled:              pulumi.Any(_var.Asset_vmware_vm_is_disks_cbt_enabled),
//					IsDisksUuidEnabled:             pulumi.Any(_var.Asset_vmware_vm_is_disks_uuid_enabled),
//					Path:                           pulumi.Any(_var.Asset_vmware_vm_path),
//					VmwareToolsStatus:              pulumi.Any(_var.Asset_vmware_vm_vmware_tools_status),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// Assets can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:CloudBridge/asset:Asset test_asset "id"
//
// ```
type Asset struct {
	pulumi.CustomResourceState

	// (Updatable) List of asset source OCID.
	AssetSourceIds pulumi.StringArrayOutput `pulumi:"assetSourceIds"`
	// (Updatable) The type of asset.
	AssetType pulumi.StringOutput `pulumi:"assetType"`
	// (Updatable) The OCID of the compartment that the asset belongs to.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Compute related properties.
	Compute AssetComputeOutput `pulumi:"compute"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Asset display name.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The key of the asset from the external environment.
	ExternalAssetKey pulumi.StringOutput `pulumi:"externalAssetKey"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Inventory ID to which an asset belongs.
	InventoryId pulumi.StringOutput `pulumi:"inventoryId"`
	// The source key to which the asset belongs.
	SourceKey pulumi.StringOutput `pulumi:"sourceKey"`
	// The current state of the asset.
	State pulumi.StringOutput `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The time when the asset was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the asset was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) Virtual machine related properties.
	Vm AssetVmOutput `pulumi:"vm"`
	// (Updatable) VMware vCenter related properties.
	VmwareVcenter AssetVmwareVcenterOutput `pulumi:"vmwareVcenter"`
	// (Updatable) VMware virtual machine related properties.
	VmwareVm AssetVmwareVmOutput `pulumi:"vmwareVm"`
}

// NewAsset registers a new resource with the given unique name, arguments, and options.
func NewAsset(ctx *pulumi.Context,
	name string, args *AssetArgs, opts ...pulumi.ResourceOption) (*Asset, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AssetType == nil {
		return nil, errors.New("invalid value for required argument 'AssetType'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ExternalAssetKey == nil {
		return nil, errors.New("invalid value for required argument 'ExternalAssetKey'")
	}
	if args.InventoryId == nil {
		return nil, errors.New("invalid value for required argument 'InventoryId'")
	}
	if args.SourceKey == nil {
		return nil, errors.New("invalid value for required argument 'SourceKey'")
	}
	var resource Asset
	err := ctx.RegisterResource("oci:CloudBridge/asset:Asset", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAsset gets an existing Asset resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAsset(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AssetState, opts ...pulumi.ResourceOption) (*Asset, error) {
	var resource Asset
	err := ctx.ReadResource("oci:CloudBridge/asset:Asset", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Asset resources.
type assetState struct {
	// (Updatable) List of asset source OCID.
	AssetSourceIds []string `pulumi:"assetSourceIds"`
	// (Updatable) The type of asset.
	AssetType *string `pulumi:"assetType"`
	// (Updatable) The OCID of the compartment that the asset belongs to.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Compute related properties.
	Compute *AssetCompute `pulumi:"compute"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Asset display name.
	DisplayName *string `pulumi:"displayName"`
	// The key of the asset from the external environment.
	ExternalAssetKey *string `pulumi:"externalAssetKey"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Inventory ID to which an asset belongs.
	InventoryId *string `pulumi:"inventoryId"`
	// The source key to which the asset belongs.
	SourceKey *string `pulumi:"sourceKey"`
	// The current state of the asset.
	State *string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time when the asset was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the asset was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) Virtual machine related properties.
	Vm *AssetVm `pulumi:"vm"`
	// (Updatable) VMware vCenter related properties.
	VmwareVcenter *AssetVmwareVcenter `pulumi:"vmwareVcenter"`
	// (Updatable) VMware virtual machine related properties.
	VmwareVm *AssetVmwareVm `pulumi:"vmwareVm"`
}

type AssetState struct {
	// (Updatable) List of asset source OCID.
	AssetSourceIds pulumi.StringArrayInput
	// (Updatable) The type of asset.
	AssetType pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that the asset belongs to.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Compute related properties.
	Compute AssetComputePtrInput
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Asset display name.
	DisplayName pulumi.StringPtrInput
	// The key of the asset from the external environment.
	ExternalAssetKey pulumi.StringPtrInput
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Inventory ID to which an asset belongs.
	InventoryId pulumi.StringPtrInput
	// The source key to which the asset belongs.
	SourceKey pulumi.StringPtrInput
	// The current state of the asset.
	State pulumi.StringPtrInput
	// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags pulumi.MapInput
	// The time when the asset was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the asset was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) Virtual machine related properties.
	Vm AssetVmPtrInput
	// (Updatable) VMware vCenter related properties.
	VmwareVcenter AssetVmwareVcenterPtrInput
	// (Updatable) VMware virtual machine related properties.
	VmwareVm AssetVmwareVmPtrInput
}

func (AssetState) ElementType() reflect.Type {
	return reflect.TypeOf((*assetState)(nil)).Elem()
}

type assetArgs struct {
	// (Updatable) List of asset source OCID.
	AssetSourceIds []string `pulumi:"assetSourceIds"`
	// (Updatable) The type of asset.
	AssetType string `pulumi:"assetType"`
	// (Updatable) The OCID of the compartment that the asset belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Compute related properties.
	Compute *AssetCompute `pulumi:"compute"`
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Asset display name.
	DisplayName *string `pulumi:"displayName"`
	// The key of the asset from the external environment.
	ExternalAssetKey string `pulumi:"externalAssetKey"`
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Inventory ID to which an asset belongs.
	InventoryId string `pulumi:"inventoryId"`
	// The source key to which the asset belongs.
	SourceKey string `pulumi:"sourceKey"`
	// (Updatable) Virtual machine related properties.
	Vm *AssetVm `pulumi:"vm"`
	// (Updatable) VMware vCenter related properties.
	VmwareVcenter *AssetVmwareVcenter `pulumi:"vmwareVcenter"`
	// (Updatable) VMware virtual machine related properties.
	VmwareVm *AssetVmwareVm `pulumi:"vmwareVm"`
}

// The set of arguments for constructing a Asset resource.
type AssetArgs struct {
	// (Updatable) List of asset source OCID.
	AssetSourceIds pulumi.StringArrayInput
	// (Updatable) The type of asset.
	AssetType pulumi.StringInput
	// (Updatable) The OCID of the compartment that the asset belongs to.
	CompartmentId pulumi.StringInput
	// (Updatable) Compute related properties.
	Compute AssetComputePtrInput
	// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Asset display name.
	DisplayName pulumi.StringPtrInput
	// The key of the asset from the external environment.
	ExternalAssetKey pulumi.StringInput
	// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Inventory ID to which an asset belongs.
	InventoryId pulumi.StringInput
	// The source key to which the asset belongs.
	SourceKey pulumi.StringInput
	// (Updatable) Virtual machine related properties.
	Vm AssetVmPtrInput
	// (Updatable) VMware vCenter related properties.
	VmwareVcenter AssetVmwareVcenterPtrInput
	// (Updatable) VMware virtual machine related properties.
	VmwareVm AssetVmwareVmPtrInput
}

func (AssetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*assetArgs)(nil)).Elem()
}

type AssetInput interface {
	pulumi.Input

	ToAssetOutput() AssetOutput
	ToAssetOutputWithContext(ctx context.Context) AssetOutput
}

func (*Asset) ElementType() reflect.Type {
	return reflect.TypeOf((**Asset)(nil)).Elem()
}

func (i *Asset) ToAssetOutput() AssetOutput {
	return i.ToAssetOutputWithContext(context.Background())
}

func (i *Asset) ToAssetOutputWithContext(ctx context.Context) AssetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AssetOutput)
}

// AssetArrayInput is an input type that accepts AssetArray and AssetArrayOutput values.
// You can construct a concrete instance of `AssetArrayInput` via:
//
//	AssetArray{ AssetArgs{...} }
type AssetArrayInput interface {
	pulumi.Input

	ToAssetArrayOutput() AssetArrayOutput
	ToAssetArrayOutputWithContext(context.Context) AssetArrayOutput
}

type AssetArray []AssetInput

func (AssetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Asset)(nil)).Elem()
}

func (i AssetArray) ToAssetArrayOutput() AssetArrayOutput {
	return i.ToAssetArrayOutputWithContext(context.Background())
}

func (i AssetArray) ToAssetArrayOutputWithContext(ctx context.Context) AssetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AssetArrayOutput)
}

// AssetMapInput is an input type that accepts AssetMap and AssetMapOutput values.
// You can construct a concrete instance of `AssetMapInput` via:
//
//	AssetMap{ "key": AssetArgs{...} }
type AssetMapInput interface {
	pulumi.Input

	ToAssetMapOutput() AssetMapOutput
	ToAssetMapOutputWithContext(context.Context) AssetMapOutput
}

type AssetMap map[string]AssetInput

func (AssetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Asset)(nil)).Elem()
}

func (i AssetMap) ToAssetMapOutput() AssetMapOutput {
	return i.ToAssetMapOutputWithContext(context.Background())
}

func (i AssetMap) ToAssetMapOutputWithContext(ctx context.Context) AssetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AssetMapOutput)
}

type AssetOutput struct{ *pulumi.OutputState }

func (AssetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Asset)(nil)).Elem()
}

func (o AssetOutput) ToAssetOutput() AssetOutput {
	return o
}

func (o AssetOutput) ToAssetOutputWithContext(ctx context.Context) AssetOutput {
	return o
}

// (Updatable) List of asset source OCID.
func (o AssetOutput) AssetSourceIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringArrayOutput { return v.AssetSourceIds }).(pulumi.StringArrayOutput)
}

// (Updatable) The type of asset.
func (o AssetOutput) AssetType() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.AssetType }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment that the asset belongs to.
func (o AssetOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Compute related properties.
func (o AssetOutput) Compute() AssetComputeOutput {
	return o.ApplyT(func(v *Asset) AssetComputeOutput { return v.Compute }).(AssetComputeOutput)
}

// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o AssetOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Asset) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Asset display name.
func (o AssetOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The key of the asset from the external environment.
func (o AssetOutput) ExternalAssetKey() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.ExternalAssetKey }).(pulumi.StringOutput)
}

// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o AssetOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Asset) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Inventory ID to which an asset belongs.
func (o AssetOutput) InventoryId() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.InventoryId }).(pulumi.StringOutput)
}

// The source key to which the asset belongs.
func (o AssetOutput) SourceKey() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.SourceKey }).(pulumi.StringOutput)
}

// The current state of the asset.
func (o AssetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o AssetOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Asset) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The time when the asset was created. An RFC3339 formatted datetime string.
func (o AssetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the asset was updated. An RFC3339 formatted datetime string.
func (o AssetOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Asset) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// (Updatable) Virtual machine related properties.
func (o AssetOutput) Vm() AssetVmOutput {
	return o.ApplyT(func(v *Asset) AssetVmOutput { return v.Vm }).(AssetVmOutput)
}

// (Updatable) VMware vCenter related properties.
func (o AssetOutput) VmwareVcenter() AssetVmwareVcenterOutput {
	return o.ApplyT(func(v *Asset) AssetVmwareVcenterOutput { return v.VmwareVcenter }).(AssetVmwareVcenterOutput)
}

// (Updatable) VMware virtual machine related properties.
func (o AssetOutput) VmwareVm() AssetVmwareVmOutput {
	return o.ApplyT(func(v *Asset) AssetVmwareVmOutput { return v.VmwareVm }).(AssetVmwareVmOutput)
}

type AssetArrayOutput struct{ *pulumi.OutputState }

func (AssetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Asset)(nil)).Elem()
}

func (o AssetArrayOutput) ToAssetArrayOutput() AssetArrayOutput {
	return o
}

func (o AssetArrayOutput) ToAssetArrayOutputWithContext(ctx context.Context) AssetArrayOutput {
	return o
}

func (o AssetArrayOutput) Index(i pulumi.IntInput) AssetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Asset {
		return vs[0].([]*Asset)[vs[1].(int)]
	}).(AssetOutput)
}

type AssetMapOutput struct{ *pulumi.OutputState }

func (AssetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Asset)(nil)).Elem()
}

func (o AssetMapOutput) ToAssetMapOutput() AssetMapOutput {
	return o
}

func (o AssetMapOutput) ToAssetMapOutputWithContext(ctx context.Context) AssetMapOutput {
	return o
}

func (o AssetMapOutput) MapIndex(k pulumi.StringInput) AssetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Asset {
		return vs[0].(map[string]*Asset)[vs[1].(string)]
	}).(AssetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AssetInput)(nil)).Elem(), &Asset{})
	pulumi.RegisterInputType(reflect.TypeOf((*AssetArrayInput)(nil)).Elem(), AssetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AssetMapInput)(nil)).Elem(), AssetMap{})
	pulumi.RegisterOutputType(AssetOutput{})
	pulumi.RegisterOutputType(AssetArrayOutput{})
	pulumi.RegisterOutputType(AssetMapOutput{})
}