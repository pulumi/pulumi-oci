// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This data source provides details about a specific Exadata Infrastructure compute managed resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Gets information about the specified Exadata infrastructure. Applies to Exadata Cloud@Customer instances only.
    /// To get information on an Exadata Cloud Service infrastructure resource, use the  [GetCloudExadataInfrastructure](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/GetCloudExadataInfrastructure) operation.
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
    ///     var testExadataInfrastructure = Oci.Database.GetExadataInfrastructure.Invoke(new()
    ///     {
    ///         ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/exadataInfrastructureCompute:ExadataInfrastructureCompute")]
    public partial class ExadataInfrastructureCompute : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The requested number of additional storage servers activated for the Exadata infrastructure.
        /// </summary>
        [Output("activatedStorageCount")]
        public Output<int> ActivatedStorageCount { get; private set; } = null!;

        [Output("activationFile")]
        public Output<string?> ActivationFile { get; private set; } = null!;

        /// <summary>
        /// The number of additional compute servers for the Exadata infrastructure.
        /// </summary>
        [Output("additionalComputeCount")]
        public Output<int> AdditionalComputeCount { get; private set; } = null!;

        [Output("additionalComputeCountComputeManagedResource")]
        public Output<int?> AdditionalComputeCountComputeManagedResource { get; private set; } = null!;

        /// <summary>
        /// Oracle Exadata System Model specification. The system model determines the amount of compute or storage server resources available for use. For more information, please see [System and Shape Configuration Options] (https://docs.oracle.com/en/engineered-systems/exadata-cloud-at-customer/ecccm/ecc-system-config-options.html#GUID-9E090174-5C57-4EB1-9243-B470F9F10D6B)
        /// </summary>
        [Output("additionalComputeSystemModel")]
        public Output<string> AdditionalComputeSystemModel { get; private set; } = null!;

        [Output("additionalComputeSystemModelComputeManagedResource")]
        public Output<string?> AdditionalComputeSystemModelComputeManagedResource { get; private set; } = null!;

        /// <summary>
        /// The requested number of additional storage servers for the Exadata infrastructure.
        /// </summary>
        [Output("additionalStorageCount")]
        public Output<int> AdditionalStorageCount { get; private set; } = null!;

        /// <summary>
        /// The CIDR block for the Exadata administration network.
        /// </summary>
        [Output("adminNetworkCidr")]
        public Output<string> AdminNetworkCidr { get; private set; } = null!;

        /// <summary>
        /// The IP address for the first control plane server.
        /// </summary>
        [Output("cloudControlPlaneServer1")]
        public Output<string> CloudControlPlaneServer1 { get; private set; } = null!;

        /// <summary>
        /// The IP address for the second control plane server.
        /// </summary>
        [Output("cloudControlPlaneServer2")]
        public Output<string> CloudControlPlaneServer2 { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The number of compute servers for the Exadata infrastructure.
        /// </summary>
        [Output("computeCount")]
        public Output<int> ComputeCount { get; private set; } = null!;

        /// <summary>
        /// The list of contacts for the Exadata infrastructure.
        /// </summary>
        [Output("contacts")]
        public Output<ImmutableArray<Outputs.ExadataInfrastructureComputeContact>> Contacts { get; private set; } = null!;

        /// <summary>
        /// The corporate network proxy for access to the control plane network.
        /// </summary>
        [Output("corporateProxy")]
        public Output<string> CorporateProxy { get; private set; } = null!;

        /// <summary>
        /// The number of enabled CPU cores.
        /// </summary>
        [Output("cpusEnabled")]
        public Output<int> CpusEnabled { get; private set; } = null!;

        [Output("createAsync")]
        public Output<bool> CreateAsync { get; private set; } = null!;

        /// <summary>
        /// The CSI Number of the Exadata infrastructure.
        /// </summary>
        [Output("csiNumber")]
        public Output<string> CsiNumber { get; private set; } = null!;

        /// <summary>
        /// Size, in terabytes, of the DATA disk group.
        /// </summary>
        [Output("dataStorageSizeInTbs")]
        public Output<double> DataStorageSizeInTbs { get; private set; } = null!;

        /// <summary>
        /// The local node storage allocated in GBs.
        /// </summary>
        [Output("dbNodeStorageSizeInGbs")]
        public Output<int> DbNodeStorageSizeInGbs { get; private set; } = null!;

        /// <summary>
        /// The software version of the database servers (dom0) in the Exadata infrastructure.
        /// </summary>
        [Output("dbServerVersion")]
        public Output<string> DbServerVersion { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        [Output("dnsServers")]
        public Output<ImmutableArray<string>> DnsServers { get; private set; } = null!;

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("exadataInfrastructureId")]
        public Output<string> ExadataInfrastructureId { get; private set; } = null!;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The gateway for the control plane network.
        /// </summary>
        [Output("gateway")]
        public Output<string> Gateway { get; private set; } = null!;

        /// <summary>
        /// The CIDR block for the Exadata InfiniBand interconnect.
        /// </summary>
        [Output("infiniBandNetworkCidr")]
        public Output<string> InfiniBandNetworkCidr { get; private set; } = null!;

        /// <summary>
        /// Indicates whether cps offline diagnostic report is enabled for this Exadata infrastructure. This will allow a customer to quickly check status themselves and fix problems on their end, saving time and frustration for both Oracle and the customer when they find the CPS in a disconnected state.You can enable offline diagnostic report during Exadata infrastructure provisioning. You can also disable or enable it at any time using the UpdateExadatainfrastructure API.
        /// </summary>
        [Output("isCpsOfflineReportEnabled")]
        public Output<bool> IsCpsOfflineReportEnabled { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// A field to capture ‘Maintenance SLO Status’ for the Exadata infrastructure with values ‘OK’, ‘DEGRADED’. Default is ‘OK’ when the infrastructure is provisioned.
        /// </summary>
        [Output("maintenanceSloStatus")]
        public Output<string> MaintenanceSloStatus { get; private set; } = null!;

        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        [Output("maintenanceWindows")]
        public Output<ImmutableArray<Outputs.ExadataInfrastructureComputeMaintenanceWindow>> MaintenanceWindows { get; private set; } = null!;

        /// <summary>
        /// The total number of CPU cores available.
        /// </summary>
        [Output("maxCpuCount")]
        public Output<int> MaxCpuCount { get; private set; } = null!;

        /// <summary>
        /// The total available DATA disk group size.
        /// </summary>
        [Output("maxDataStorageInTbs")]
        public Output<double> MaxDataStorageInTbs { get; private set; } = null!;

        /// <summary>
        /// The total local node storage available in GBs.
        /// </summary>
        [Output("maxDbNodeStorageInGbs")]
        public Output<int> MaxDbNodeStorageInGbs { get; private set; } = null!;

        /// <summary>
        /// The total memory available in GBs.
        /// </summary>
        [Output("maxMemoryInGbs")]
        public Output<int> MaxMemoryInGbs { get; private set; } = null!;

        /// <summary>
        /// The memory allocated in GBs.
        /// </summary>
        [Output("memorySizeInGbs")]
        public Output<int> MemorySizeInGbs { get; private set; } = null!;

        /// <summary>
        /// The monthly software version of the database servers (dom0) in the Exadata infrastructure.
        /// </summary>
        [Output("monthlyDbServerVersion")]
        public Output<string> MonthlyDbServerVersion { get; private set; } = null!;

        /// <summary>
        /// The netmask for the control plane network.
        /// </summary>
        [Output("netmask")]
        public Output<string> Netmask { get; private set; } = null!;

        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        [Output("ntpServers")]
        public Output<ImmutableArray<string>> NtpServers { get; private set; } = null!;

        /// <summary>
        /// The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
        /// </summary>
        [Output("shape")]
        public Output<string> Shape { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the Exadata infrastructure.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The number of Exadata storage servers for the Exadata infrastructure.
        /// </summary>
        [Output("storageCount")]
        public Output<int> StorageCount { get; private set; } = null!;

        /// <summary>
        /// The software version of the storage servers (cells) in the Exadata infrastructure.
        /// </summary>
        [Output("storageServerVersion")]
        public Output<string> StorageServerVersion { get; private set; } = null!;

        /// <summary>
        /// The date and time the Exadata infrastructure was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        [Output("timeZone")]
        public Output<string> TimeZone { get; private set; } = null!;


        /// <summary>
        /// Create a ExadataInfrastructureCompute resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExadataInfrastructureCompute(string name, ExadataInfrastructureComputeArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/exadataInfrastructureCompute:ExadataInfrastructureCompute", name, args ?? new ExadataInfrastructureComputeArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExadataInfrastructureCompute(string name, Input<string> id, ExadataInfrastructureComputeState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/exadataInfrastructureCompute:ExadataInfrastructureCompute", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExadataInfrastructureCompute resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExadataInfrastructureCompute Get(string name, Input<string> id, ExadataInfrastructureComputeState? state = null, CustomResourceOptions? options = null)
        {
            return new ExadataInfrastructureCompute(name, id, state, options);
        }
    }

    public sealed class ExadataInfrastructureComputeArgs : global::Pulumi.ResourceArgs
    {
        [Input("activationFile")]
        public Input<string>? ActivationFile { get; set; }

        [Input("additionalComputeCountComputeManagedResource")]
        public Input<int>? AdditionalComputeCountComputeManagedResource { get; set; }

        [Input("additionalComputeSystemModelComputeManagedResource")]
        public Input<string>? AdditionalComputeSystemModelComputeManagedResource { get; set; }

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public Input<string> ExadataInfrastructureId { get; set; } = null!;

        public ExadataInfrastructureComputeArgs()
        {
        }
        public static new ExadataInfrastructureComputeArgs Empty => new ExadataInfrastructureComputeArgs();
    }

    public sealed class ExadataInfrastructureComputeState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The requested number of additional storage servers activated for the Exadata infrastructure.
        /// </summary>
        [Input("activatedStorageCount")]
        public Input<int>? ActivatedStorageCount { get; set; }

        [Input("activationFile")]
        public Input<string>? ActivationFile { get; set; }

        /// <summary>
        /// The number of additional compute servers for the Exadata infrastructure.
        /// </summary>
        [Input("additionalComputeCount")]
        public Input<int>? AdditionalComputeCount { get; set; }

        [Input("additionalComputeCountComputeManagedResource")]
        public Input<int>? AdditionalComputeCountComputeManagedResource { get; set; }

        /// <summary>
        /// Oracle Exadata System Model specification. The system model determines the amount of compute or storage server resources available for use. For more information, please see [System and Shape Configuration Options] (https://docs.oracle.com/en/engineered-systems/exadata-cloud-at-customer/ecccm/ecc-system-config-options.html#GUID-9E090174-5C57-4EB1-9243-B470F9F10D6B)
        /// </summary>
        [Input("additionalComputeSystemModel")]
        public Input<string>? AdditionalComputeSystemModel { get; set; }

        [Input("additionalComputeSystemModelComputeManagedResource")]
        public Input<string>? AdditionalComputeSystemModelComputeManagedResource { get; set; }

        /// <summary>
        /// The requested number of additional storage servers for the Exadata infrastructure.
        /// </summary>
        [Input("additionalStorageCount")]
        public Input<int>? AdditionalStorageCount { get; set; }

        /// <summary>
        /// The CIDR block for the Exadata administration network.
        /// </summary>
        [Input("adminNetworkCidr")]
        public Input<string>? AdminNetworkCidr { get; set; }

        /// <summary>
        /// The IP address for the first control plane server.
        /// </summary>
        [Input("cloudControlPlaneServer1")]
        public Input<string>? CloudControlPlaneServer1 { get; set; }

        /// <summary>
        /// The IP address for the second control plane server.
        /// </summary>
        [Input("cloudControlPlaneServer2")]
        public Input<string>? CloudControlPlaneServer2 { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The number of compute servers for the Exadata infrastructure.
        /// </summary>
        [Input("computeCount")]
        public Input<int>? ComputeCount { get; set; }

        [Input("contacts")]
        private InputList<Inputs.ExadataInfrastructureComputeContactGetArgs>? _contacts;

        /// <summary>
        /// The list of contacts for the Exadata infrastructure.
        /// </summary>
        public InputList<Inputs.ExadataInfrastructureComputeContactGetArgs> Contacts
        {
            get => _contacts ?? (_contacts = new InputList<Inputs.ExadataInfrastructureComputeContactGetArgs>());
            set => _contacts = value;
        }

        /// <summary>
        /// The corporate network proxy for access to the control plane network.
        /// </summary>
        [Input("corporateProxy")]
        public Input<string>? CorporateProxy { get; set; }

        /// <summary>
        /// The number of enabled CPU cores.
        /// </summary>
        [Input("cpusEnabled")]
        public Input<int>? CpusEnabled { get; set; }

        [Input("createAsync")]
        public Input<bool>? CreateAsync { get; set; }

        /// <summary>
        /// The CSI Number of the Exadata infrastructure.
        /// </summary>
        [Input("csiNumber")]
        public Input<string>? CsiNumber { get; set; }

        /// <summary>
        /// Size, in terabytes, of the DATA disk group.
        /// </summary>
        [Input("dataStorageSizeInTbs")]
        public Input<double>? DataStorageSizeInTbs { get; set; }

        /// <summary>
        /// The local node storage allocated in GBs.
        /// </summary>
        [Input("dbNodeStorageSizeInGbs")]
        public Input<int>? DbNodeStorageSizeInGbs { get; set; }

        /// <summary>
        /// The software version of the database servers (dom0) in the Exadata infrastructure.
        /// </summary>
        [Input("dbServerVersion")]
        public Input<string>? DbServerVersion { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("dnsServers")]
        private InputList<string>? _dnsServers;

        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public InputList<string> DnsServers
        {
            get => _dnsServers ?? (_dnsServers = new InputList<string>());
            set => _dnsServers = value;
        }

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId")]
        public Input<string>? ExadataInfrastructureId { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The gateway for the control plane network.
        /// </summary>
        [Input("gateway")]
        public Input<string>? Gateway { get; set; }

        /// <summary>
        /// The CIDR block for the Exadata InfiniBand interconnect.
        /// </summary>
        [Input("infiniBandNetworkCidr")]
        public Input<string>? InfiniBandNetworkCidr { get; set; }

        /// <summary>
        /// Indicates whether cps offline diagnostic report is enabled for this Exadata infrastructure. This will allow a customer to quickly check status themselves and fix problems on their end, saving time and frustration for both Oracle and the customer when they find the CPS in a disconnected state.You can enable offline diagnostic report during Exadata infrastructure provisioning. You can also disable or enable it at any time using the UpdateExadatainfrastructure API.
        /// </summary>
        [Input("isCpsOfflineReportEnabled")]
        public Input<bool>? IsCpsOfflineReportEnabled { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// A field to capture ‘Maintenance SLO Status’ for the Exadata infrastructure with values ‘OK’, ‘DEGRADED’. Default is ‘OK’ when the infrastructure is provisioned.
        /// </summary>
        [Input("maintenanceSloStatus")]
        public Input<string>? MaintenanceSloStatus { get; set; }

        [Input("maintenanceWindows")]
        private InputList<Inputs.ExadataInfrastructureComputeMaintenanceWindowGetArgs>? _maintenanceWindows;

        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public InputList<Inputs.ExadataInfrastructureComputeMaintenanceWindowGetArgs> MaintenanceWindows
        {
            get => _maintenanceWindows ?? (_maintenanceWindows = new InputList<Inputs.ExadataInfrastructureComputeMaintenanceWindowGetArgs>());
            set => _maintenanceWindows = value;
        }

        /// <summary>
        /// The total number of CPU cores available.
        /// </summary>
        [Input("maxCpuCount")]
        public Input<int>? MaxCpuCount { get; set; }

        /// <summary>
        /// The total available DATA disk group size.
        /// </summary>
        [Input("maxDataStorageInTbs")]
        public Input<double>? MaxDataStorageInTbs { get; set; }

        /// <summary>
        /// The total local node storage available in GBs.
        /// </summary>
        [Input("maxDbNodeStorageInGbs")]
        public Input<int>? MaxDbNodeStorageInGbs { get; set; }

        /// <summary>
        /// The total memory available in GBs.
        /// </summary>
        [Input("maxMemoryInGbs")]
        public Input<int>? MaxMemoryInGbs { get; set; }

        /// <summary>
        /// The memory allocated in GBs.
        /// </summary>
        [Input("memorySizeInGbs")]
        public Input<int>? MemorySizeInGbs { get; set; }

        /// <summary>
        /// The monthly software version of the database servers (dom0) in the Exadata infrastructure.
        /// </summary>
        [Input("monthlyDbServerVersion")]
        public Input<string>? MonthlyDbServerVersion { get; set; }

        /// <summary>
        /// The netmask for the control plane network.
        /// </summary>
        [Input("netmask")]
        public Input<string>? Netmask { get; set; }

        [Input("ntpServers")]
        private InputList<string>? _ntpServers;

        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public InputList<string> NtpServers
        {
            get => _ntpServers ?? (_ntpServers = new InputList<string>());
            set => _ntpServers = value;
        }

        /// <summary>
        /// The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// The current lifecycle state of the Exadata infrastructure.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The number of Exadata storage servers for the Exadata infrastructure.
        /// </summary>
        [Input("storageCount")]
        public Input<int>? StorageCount { get; set; }

        /// <summary>
        /// The software version of the storage servers (cells) in the Exadata infrastructure.
        /// </summary>
        [Input("storageServerVersion")]
        public Input<string>? StorageServerVersion { get; set; }

        /// <summary>
        /// The date and time the Exadata infrastructure was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        public ExadataInfrastructureComputeState()
        {
        }
        public static new ExadataInfrastructureComputeState Empty => new ExadataInfrastructureComputeState();
    }
}