// *** WARNING: this file was generated by pulumi-language-dotnet. ***
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
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testAsset = new Oci.CloudBridge.Asset("test_asset", new()
    ///     {
    ///         AssetType = assetAssetType,
    ///         CompartmentId = compartmentId,
    ///         ExternalAssetKey = assetExternalAssetKey,
    ///         InventoryId = testInventory.Id,
    ///         SourceKey = assetSourceKey,
    ///         AssetSourceIds = assetAssetSourceIds,
    ///         Compute = new Oci.CloudBridge.Inputs.AssetComputeArgs
    ///         {
    ///             ConnectedNetworks = assetComputeConnectedNetworks,
    ///             CoresCount = assetComputeCoresCount,
    ///             CpuModel = assetComputeCpuModel,
    ///             Description = assetComputeDescription,
    ///             Disks = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeDiskArgs
    ///                 {
    ///                     BootOrder = assetComputeDisksBootOrder,
    ///                     Location = assetComputeDisksLocation,
    ///                     Name = assetComputeDisksName,
    ///                     PersistentMode = assetComputeDisksPersistentMode,
    ///                     SizeInMbs = assetComputeDisksSizeInMbs,
    ///                     Uuid = assetComputeDisksUuid,
    ///                     UuidLun = assetComputeDisksUuidLun,
    ///                 },
    ///             },
    ///             DisksCount = assetComputeDisksCount,
    ///             DnsName = assetComputeDnsName,
    ///             Firmware = assetComputeFirmware,
    ///             GpuDevices = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeGpuDeviceArgs
    ///                 {
    ///                     CoresCount = assetComputeGpuDevicesCoresCount,
    ///                     Description = assetComputeGpuDevicesDescription,
    ///                     Manufacturer = assetComputeGpuDevicesManufacturer,
    ///                     MemoryInMbs = assetComputeGpuDevicesMemoryInMbs,
    ///                     Name = assetComputeGpuDevicesName,
    ///                 },
    ///             },
    ///             GpuDevicesCount = assetComputeGpuDevicesCount,
    ///             GuestState = assetComputeGuestState,
    ///             HardwareVersion = assetComputeHardwareVersion,
    ///             HostName = assetComputeHostName,
    ///             IsPmemEnabled = assetComputeIsPmemEnabled,
    ///             IsTpmEnabled = assetComputeIsTpmEnabled,
    ///             LatencySensitivity = assetComputeLatencySensitivity,
    ///             MemoryInMbs = assetComputeMemoryInMbs,
    ///             Nics = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeNicArgs
    ///                 {
    ///                     IpAddresses = assetComputeNicsIpAddresses,
    ///                     Label = assetComputeNicsLabel,
    ///                     MacAddress = assetComputeNicsMacAddress,
    ///                     MacAddressType = assetComputeNicsMacAddressType,
    ///                     NetworkName = assetComputeNicsNetworkName,
    ///                     SwitchName = assetComputeNicsSwitchName,
    ///                 },
    ///             },
    ///             NicsCount = assetComputeNicsCount,
    ///             NvdimmController = new Oci.CloudBridge.Inputs.AssetComputeNvdimmControllerArgs
    ///             {
    ///                 BusNumber = assetComputeNvdimmControllerBusNumber,
    ///                 Label = assetComputeNvdimmControllerLabel,
    ///             },
    ///             Nvdimms = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetComputeNvdimmArgs
    ///                 {
    ///                     ControllerKey = assetComputeNvdimmsControllerKey,
    ///                     Label = assetComputeNvdimmsLabel,
    ///                     UnitNumber = assetComputeNvdimmsUnitNumber,
    ///                 },
    ///             },
    ///             OperatingSystem = assetComputeOperatingSystem,
    ///             OperatingSystemVersion = assetComputeOperatingSystemVersion,
    ///             PmemInMbs = assetComputePmemInMbs,
    ///             PowerState = assetComputePowerState,
    ///             PrimaryIp = assetComputePrimaryIp,
    ///             ScsiController = new Oci.CloudBridge.Inputs.AssetComputeScsiControllerArgs
    ///             {
    ///                 Label = assetComputeScsiControllerLabel,
    ///                 SharedBus = assetComputeScsiControllerSharedBus,
    ///                 UnitNumber = assetComputeScsiControllerUnitNumber,
    ///             },
    ///             StorageProvisionedInMbs = assetComputeStorageProvisionedInMbs,
    ///             ThreadsPerCoreCount = assetComputeThreadsPerCoreCount,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         DisplayName = assetDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         Vm = new Oci.CloudBridge.Inputs.AssetVmArgs
    ///         {
    ///             HypervisorHost = assetVmHypervisorHost,
    ///             HypervisorVendor = assetVmHypervisorVendor,
    ///             HypervisorVersion = assetVmHypervisorVersion,
    ///         },
    ///         VmwareVcenter = new Oci.CloudBridge.Inputs.AssetVmwareVcenterArgs
    ///         {
    ///             DataCenter = assetVmwareVcenterDataCenter,
    ///             VcenterKey = assetVmwareVcenterVcenterKey,
    ///             VcenterVersion = assetVmwareVcenterVcenterVersion,
    ///         },
    ///         VmwareVm = new Oci.CloudBridge.Inputs.AssetVmwareVmArgs
    ///         {
    ///             Cluster = assetVmwareVmCluster,
    ///             CustomerFields = assetVmwareVmCustomerFields,
    ///             CustomerTags = new[]
    ///             {
    ///                 new Oci.CloudBridge.Inputs.AssetVmwareVmCustomerTagArgs
    ///                 {
    ///                     Description = assetVmwareVmCustomerTagsDescription,
    ///                     Name = assetVmwareVmCustomerTagsName,
    ///                 },
    ///             },
    ///             FaultToleranceBandwidth = assetVmwareVmFaultToleranceBandwidth,
    ///             FaultToleranceSecondaryLatency = assetVmwareVmFaultToleranceSecondaryLatency,
    ///             FaultToleranceState = assetVmwareVmFaultToleranceState,
    ///             InstanceUuid = assetVmwareVmInstanceUuid,
    ///             IsDisksCbtEnabled = assetVmwareVmIsDisksCbtEnabled,
    ///             IsDisksUuidEnabled = assetVmwareVmIsDisksUuidEnabled,
    ///             Path = assetVmwareVmPath,
    ///             VmwareToolsStatus = assetVmwareVmVmwareToolsStatus,
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
    /// $ pulumi import oci:CloudBridge/asset:Asset test_asset "id"
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
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

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
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

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
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

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
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
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
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
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
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
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
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
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
        private InputMap<string>? _systemTags;

        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
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
