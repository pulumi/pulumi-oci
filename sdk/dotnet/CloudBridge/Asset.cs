// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge
{
    /// <summary>
    /// This resource provides the Asset resource in Oracle Cloud Infrastructure Cloud Bridge service.
    /// 
    /// Creates an asset.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testAsset = new Oci.CloudBridge.Asset("testAsset", new()
    ///     {
    ///         AssetType = @var.Asset_asset_type,
    ///         CompartmentId = @var.Compartment_id,
    ///         ExternalAssetKey = @var.Asset_external_asset_key,
    ///         InventoryId = oci_cloud_bridge_inventory.Test_inventory.Id,
    ///         SourceKey = @var.Asset_source_key,
    ///         AssetSourceIds = @var.Asset_asset_source_ids,
    ///         Compute = new Oci.CloudBridge.Inputs.AssetComputeArgs
    ///         {
    ///             ConnectedNetworks = @var.Asset_compute_connected_networks,
    ///             CoresCount = @var.Asset_compute_cores_count,
    ///             CpuModel = @var.Asset_compute_cpu_model,
    ///             Description = @var.Asset_compute_description,
    ///             Disks = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeDiskArgs
    ///                 {
    ///                     BootOrder = @var.Asset_compute_disks_boot_order,
    ///                     Location = @var.Asset_compute_disks_location,
    ///                     Name = @var.Asset_compute_disks_name,
    ///                     PersistentMode = @var.Asset_compute_disks_persistent_mode,
    ///                     SizeInMbs = @var.Asset_compute_disks_size_in_mbs,
    ///                     Uuid = @var.Asset_compute_disks_uuid,
    ///                     UuidLun = @var.Asset_compute_disks_uuid_lun,
    ///                 },
    ///             },
    ///             DisksCount = @var.Asset_compute_disks_count,
    ///             DnsName = @var.Asset_compute_dns_name,
    ///             Firmware = @var.Asset_compute_firmware,
    ///             GpuDevices = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeGpuDeviceArgs
    ///                 {
    ///                     CoresCount = @var.Asset_compute_gpu_devices_cores_count,
    ///                     Description = @var.Asset_compute_gpu_devices_description,
    ///                     Manufacturer = @var.Asset_compute_gpu_devices_manufacturer,
    ///                     MemoryInMbs = @var.Asset_compute_gpu_devices_memory_in_mbs,
    ///                     Name = @var.Asset_compute_gpu_devices_name,
    ///                 },
    ///             },
    ///             GpuDevicesCount = @var.Asset_compute_gpu_devices_count,
    ///             GuestState = @var.Asset_compute_guest_state,
    ///             HardwareVersion = @var.Asset_compute_hardware_version,
    ///             HostName = @var.Asset_compute_host_name,
    ///             IsPmemEnabled = @var.Asset_compute_is_pmem_enabled,
    ///             IsTpmEnabled = @var.Asset_compute_is_tpm_enabled,
    ///             LatencySensitivity = @var.Asset_compute_latency_sensitivity,
    ///             MemoryInMbs = @var.Asset_compute_memory_in_mbs,
    ///             Nics = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeNicArgs
    ///                 {
    ///                     IpAddresses = @var.Asset_compute_nics_ip_addresses,
    ///                     Label = @var.Asset_compute_nics_label,
    ///                     MacAddress = @var.Asset_compute_nics_mac_address,
    ///                     MacAddressType = @var.Asset_compute_nics_mac_address_type,
    ///                     NetworkName = @var.Asset_compute_nics_network_name,
    ///                     SwitchName = @var.Asset_compute_nics_switch_name,
    ///                 },
    ///             },
    ///             NicsCount = @var.Asset_compute_nics_count,
    ///             NvdimmController = new Oci.CloudBridge.Inputs.AssetComputeNvdimmControllerArgs
    ///             {
    ///                 BusNumber = @var.Asset_compute_nvdimm_controller_bus_number,
    ///                 Label = @var.Asset_compute_nvdimm_controller_label,
    ///             },
    ///             Nvdimms = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeNvdimmArgs
    ///                 {
    ///                     ControllerKey = @var.Asset_compute_nvdimms_controller_key,
    ///                     Label = @var.Asset_compute_nvdimms_label,
    ///                     UnitNumber = @var.Asset_compute_nvdimms_unit_number,
    ///                 },
    ///             },
    ///             OperatingSystem = @var.Asset_compute_operating_system,
    ///             OperatingSystemVersion = @var.Asset_compute_operating_system_version,
    ///             PmemInMbs = @var.Asset_compute_pmem_in_mbs,
    ///             PowerState = @var.Asset_compute_power_state,
    ///             PrimaryIp = @var.Asset_compute_primary_ip,
    ///             ScsiController = new Oci.CloudBridge.Inputs.AssetComputeScsiControllerArgs
    ///             {
    ///                 Label = @var.Asset_compute_scsi_controller_label,
    ///                 SharedBus = @var.Asset_compute_scsi_controller_shared_bus,
    ///                 UnitNumber = @var.Asset_compute_scsi_controller_unit_number,
    ///             },
    ///             StorageProvisionedInMbs = @var.Asset_compute_storage_provisioned_in_mbs,
    ///             ThreadsPerCoreCount = @var.Asset_compute_threads_per_core_count,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         DisplayName = @var.Asset_display_name,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         Vm = new Oci.CloudBridge.Inputs.AssetVmArgs
    ///         {
    ///             HypervisorHost = @var.Asset_vm_hypervisor_host,
    ///             HypervisorVendor = @var.Asset_vm_hypervisor_vendor,
    ///             HypervisorVersion = @var.Asset_vm_hypervisor_version,
    ///         },
    ///         VmwareVcenter = new Oci.CloudBridge.Inputs.AssetVmwareVcenterArgs
    ///         {
    ///             DataCenter = @var.Asset_vmware_vcenter_data_center,
    ///             VcenterKey = @var.Asset_vmware_vcenter_vcenter_key,
    ///             VcenterVersion = @var.Asset_vmware_vcenter_vcenter_version,
    ///         },
    ///         VmwareVm = new Oci.CloudBridge.Inputs.AssetVmwareVmArgs
    ///         {
    ///             Cluster = @var.Asset_vmware_vm_cluster,
    ///             CustomerFields = @var.Asset_vmware_vm_customer_fields,
    ///             CustomerTags = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetVmwareVmCustomerTagArgs
    ///                 {
    ///                     Description = @var.Asset_vmware_vm_customer_tags_description,
    ///                     Name = @var.Asset_vmware_vm_customer_tags_name,
    ///                 },
    ///             },
    ///             FaultToleranceBandwidth = @var.Asset_vmware_vm_fault_tolerance_bandwidth,
    ///             FaultToleranceSecondaryLatency = @var.Asset_vmware_vm_fault_tolerance_secondary_latency,
    ///             FaultToleranceState = @var.Asset_vmware_vm_fault_tolerance_state,
    ///             InstanceUuid = @var.Asset_vmware_vm_instance_uuid,
    ///             IsDisksCbtEnabled = @var.Asset_vmware_vm_is_disks_cbt_enabled,
    ///             IsDisksUuidEnabled = @var.Asset_vmware_vm_is_disks_uuid_enabled,
    ///             Path = @var.Asset_vmware_vm_path,
    ///             VmwareToolsStatus = @var.Asset_vmware_vm_vmware_tools_status,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Assets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:CloudBridge/asset:Asset test_asset "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CloudBridge/asset:Asset")]
    public partial class Asset : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) List of asset source OCID.
        /// </summary>
        [Output("assetSourceIds")]
        public Output<ImmutableArray<string>> AssetSourceIds { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The type of asset.
        /// </summary>
        [Output("assetType")]
        public Output<string> AssetType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment that the asset belongs to.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Compute related properties.
        /// </summary>
        [Output("compute")]
        public Output<Outputs.AssetCompute> Compute { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Asset display name.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The key of the asset from the external environment.
        /// </summary>
        [Output("externalAssetKey")]
        public Output<string> ExternalAssetKey { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Inventory ID to which an asset belongs.
        /// </summary>
        [Output("inventoryId")]
        public Output<string> InventoryId { get; private set; } = null!;

        /// <summary>
        /// The source key to which the asset belongs.
        /// </summary>
        [Output("sourceKey")]
        public Output<string> SourceKey { get; private set; } = null!;

        /// <summary>
        /// The current state of the asset.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when the asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Virtual machine related properties.
        /// </summary>
        [Output("vm")]
        public Output<Outputs.AssetVm> Vm { get; private set; } = null!;

        /// <summary>
        /// (Updatable) VMware vCenter related properties.
        /// </summary>
        [Output("vmwareVcenter")]
        public Output<Outputs.AssetVmwareVcenter> VmwareVcenter { get; private set; } = null!;

        /// <summary>
        /// (Updatable) VMware virtual machine related properties.
        /// </summary>
        [Output("vmwareVm")]
        public Output<Outputs.AssetVmwareVm> VmwareVm { get; private set; } = null!;


        /// <summary>
        /// Create a Asset resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Asset(string name, AssetArgs args, CustomResourceOptions? options = null)
            : base("oci:CloudBridge/asset:Asset", name, args ?? new AssetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Asset(string name, Input<string> id, AssetState? state = null, CustomResourceOptions? options = null)
            : base("oci:CloudBridge/asset:Asset", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Asset resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Asset Get(string name, Input<string> id, AssetState? state = null, CustomResourceOptions? options = null)
        {
            return new Asset(name, id, state, options);
        }
    }

    public sealed class AssetArgs : global::Pulumi.ResourceArgs
    {
        [Input("assetSourceIds")]
        private InputList<string>? _assetSourceIds;

        /// <summary>
        /// (Updatable) List of asset source OCID.
        /// </summary>
        public InputList<string> AssetSourceIds
        {
            get => _assetSourceIds ?? (_assetSourceIds = new InputList<string>());
            set => _assetSourceIds = value;
        }

        /// <summary>
        /// (Updatable) The type of asset.
        /// </summary>
        [Input("assetType", required: true)]
        public Input<string> AssetType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment that the asset belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Compute related properties.
        /// </summary>
        [Input("compute")]
        public Input<Inputs.AssetComputeArgs>? Compute { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Asset display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The key of the asset from the external environment.
        /// </summary>
        [Input("externalAssetKey", required: true)]
        public Input<string> ExternalAssetKey { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Inventory ID to which an asset belongs.
        /// </summary>
        [Input("inventoryId", required: true)]
        public Input<string> InventoryId { get; set; } = null!;

        /// <summary>
        /// The source key to which the asset belongs.
        /// </summary>
        [Input("sourceKey", required: true)]
        public Input<string> SourceKey { get; set; } = null!;

        /// <summary>
        /// (Updatable) Virtual machine related properties.
        /// </summary>
        [Input("vm")]
        public Input<Inputs.AssetVmArgs>? Vm { get; set; }

        /// <summary>
        /// (Updatable) VMware vCenter related properties.
        /// </summary>
        [Input("vmwareVcenter")]
        public Input<Inputs.AssetVmwareVcenterArgs>? VmwareVcenter { get; set; }

        /// <summary>
        /// (Updatable) VMware virtual machine related properties.
        /// </summary>
        [Input("vmwareVm")]
        public Input<Inputs.AssetVmwareVmArgs>? VmwareVm { get; set; }

        public AssetArgs()
        {
        }
        public static new AssetArgs Empty => new AssetArgs();
    }

    public sealed class AssetState : global::Pulumi.ResourceArgs
    {
        [Input("assetSourceIds")]
        private InputList<string>? _assetSourceIds;

        /// <summary>
        /// (Updatable) List of asset source OCID.
        /// </summary>
        public InputList<string> AssetSourceIds
        {
            get => _assetSourceIds ?? (_assetSourceIds = new InputList<string>());
            set => _assetSourceIds = value;
        }

        /// <summary>
        /// (Updatable) The type of asset.
        /// </summary>
        [Input("assetType")]
        public Input<string>? AssetType { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment that the asset belongs to.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Compute related properties.
        /// </summary>
        [Input("compute")]
        public Input<Inputs.AssetComputeGetArgs>? Compute { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Asset display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The key of the asset from the external environment.
        /// </summary>
        [Input("externalAssetKey")]
        public Input<string>? ExternalAssetKey { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Inventory ID to which an asset belongs.
        /// </summary>
        [Input("inventoryId")]
        public Input<string>? InventoryId { get; set; }

        /// <summary>
        /// The source key to which the asset belongs.
        /// </summary>
        [Input("sourceKey")]
        public Input<string>? SourceKey { get; set; }

        /// <summary>
        /// The current state of the asset.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time when the asset was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the asset was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) Virtual machine related properties.
        /// </summary>
        [Input("vm")]
        public Input<Inputs.AssetVmGetArgs>? Vm { get; set; }

        /// <summary>
        /// (Updatable) VMware vCenter related properties.
        /// </summary>
        [Input("vmwareVcenter")]
        public Input<Inputs.AssetVmwareVcenterGetArgs>? VmwareVcenter { get; set; }

        /// <summary>
        /// (Updatable) VMware virtual machine related properties.
        /// </summary>
        [Input("vmwareVm")]
        public Input<Inputs.AssetVmwareVmGetArgs>? VmwareVm { get; set; }

        public AssetState()
        {
        }
        public static new AssetState Empty => new AssetState();
    }
}