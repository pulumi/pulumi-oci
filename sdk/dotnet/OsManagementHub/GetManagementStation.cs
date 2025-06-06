// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetManagementStation
    {
        /// <summary>
        /// This data source provides details about a specific Management Station resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified management station.
        /// 
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
        ///     var testManagementStation = Oci.OsManagementHub.GetManagementStation.Invoke(new()
        ///     {
        ///         ManagementStationId = testManagementStationOciOsManagementHubManagementStation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagementStationResult> InvokeAsync(GetManagementStationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagementStationResult>("oci:OsManagementHub/getManagementStation:getManagementStation", args ?? new GetManagementStationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Management Station resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified management station.
        /// 
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
        ///     var testManagementStation = Oci.OsManagementHub.GetManagementStation.Invoke(new()
        ///     {
        ///         ManagementStationId = testManagementStationOciOsManagementHubManagementStation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementStationResult> Invoke(GetManagementStationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementStationResult>("oci:OsManagementHub/getManagementStation:getManagementStation", args ?? new GetManagementStationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Management Station resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified management station.
        /// 
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
        ///     var testManagementStation = Oci.OsManagementHub.GetManagementStation.Invoke(new()
        ///     {
        ///         ManagementStationId = testManagementStationOciOsManagementHubManagementStation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementStationResult> Invoke(GetManagementStationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementStationResult>("oci:OsManagementHub/getManagementStation:getManagementStation", args ?? new GetManagementStationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagementStationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        /// </summary>
        [Input("managementStationId", required: true)]
        public string ManagementStationId { get; set; } = null!;

        public GetManagementStationArgs()
        {
        }
        public static new GetManagementStationArgs Empty => new GetManagementStationArgs();
    }

    public sealed class GetManagementStationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        /// </summary>
        [Input("managementStationId", required: true)]
        public Input<string> ManagementStationId { get; set; } = null!;

        public GetManagementStationInvokeArgs()
        {
        }
        public static new GetManagementStationInvokeArgs Empty => new GetManagementStationInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagementStationResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the management station.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Explanation of the health status.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User-friendly name for the management station.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Overall health information of the management station.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementStationHealthResult> Healths;
        /// <summary>
        /// Hostname of the management station.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// When enabled, the station setup script automatically runs to configure the firewall and SELinux settings on the station.
        /// </summary>
        public readonly bool IsAutoConfigEnabled;
        /// <summary>
        /// The location of the instance that is acting as the management station.
        /// </summary>
        public readonly string Location;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance that is acting as the management station.
        /// </summary>
        public readonly string ManagedInstanceId;
        public readonly string ManagementStationId;
        /// <summary>
        /// A decimal number representing the amount of mirror capacity used by the sync.
        /// </summary>
        public readonly int MirrorCapacity;
        /// <summary>
        /// The total number of all packages within the mirrored software sources.
        /// </summary>
        public readonly int MirrorPackageCount;
        /// <summary>
        /// The total size of all software source mirrors in bytes.
        /// </summary>
        public readonly string MirrorSize;
        /// <summary>
        /// Amount of available mirror storage in bytes.
        /// </summary>
        public readonly string MirrorStorageAvailableSize;
        /// <summary>
        /// Total mirror storage size in bytes.
        /// </summary>
        public readonly string MirrorStorageSize;
        /// <summary>
        /// Status summary of the mirror sync.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementStationMirrorSyncStatusResult> MirrorSyncStatuses;
        /// <summary>
        /// The total number of unique packages within the mirrored software sources on the station. Each package is counted only once, regardless of how many versions it has.
        /// </summary>
        public readonly int MirrorUniquePackageCount;
        /// <summary>
        /// Mirror information used for the management station configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementStationMirrorResult> Mirrors;
        /// <summary>
        /// A decimal number representing the progress of the current mirror sync.
        /// </summary>
        public readonly int OverallPercentage;
        /// <summary>
        /// Current state of the mirror sync for the management station.
        /// </summary>
        public readonly string OverallState;
        /// <summary>
        /// A list of other management stations that are behind the same load balancer within a high availability configuration. Stations are identified as peers if they have the same hostname and compartment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementStationPeerManagementStationResult> PeerManagementStations;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile used for the management station.
        /// </summary>
        public readonly string ProfileId;
        /// <summary>
        /// Proxy information used for the management station configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementStationProxyResult> Proxies;
        public readonly int RefreshTrigger;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the scheduled job for the mirror sync.
        /// </summary>
        public readonly string ScheduledJobId;
        /// <summary>
        /// The current state of the management station.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The number of software sources that the station is mirroring.
        /// </summary>
        public readonly int TotalMirrors;

        [OutputConstructor]
        private GetManagementStationResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            ImmutableArray<Outputs.GetManagementStationHealthResult> healths,

            string hostname,

            string id,

            bool isAutoConfigEnabled,

            string location,

            string managedInstanceId,

            string managementStationId,

            int mirrorCapacity,

            int mirrorPackageCount,

            string mirrorSize,

            string mirrorStorageAvailableSize,

            string mirrorStorageSize,

            ImmutableArray<Outputs.GetManagementStationMirrorSyncStatusResult> mirrorSyncStatuses,

            int mirrorUniquePackageCount,

            ImmutableArray<Outputs.GetManagementStationMirrorResult> mirrors,

            int overallPercentage,

            string overallState,

            ImmutableArray<Outputs.GetManagementStationPeerManagementStationResult> peerManagementStations,

            string profileId,

            ImmutableArray<Outputs.GetManagementStationProxyResult> proxies,

            int refreshTrigger,

            string scheduledJobId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            int totalMirrors)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Healths = healths;
            Hostname = hostname;
            Id = id;
            IsAutoConfigEnabled = isAutoConfigEnabled;
            Location = location;
            ManagedInstanceId = managedInstanceId;
            ManagementStationId = managementStationId;
            MirrorCapacity = mirrorCapacity;
            MirrorPackageCount = mirrorPackageCount;
            MirrorSize = mirrorSize;
            MirrorStorageAvailableSize = mirrorStorageAvailableSize;
            MirrorStorageSize = mirrorStorageSize;
            MirrorSyncStatuses = mirrorSyncStatuses;
            MirrorUniquePackageCount = mirrorUniquePackageCount;
            Mirrors = mirrors;
            OverallPercentage = overallPercentage;
            OverallState = overallState;
            PeerManagementStations = peerManagementStations;
            ProfileId = profileId;
            Proxies = proxies;
            RefreshTrigger = refreshTrigger;
            ScheduledJobId = scheduledJobId;
            State = state;
            SystemTags = systemTags;
            TotalMirrors = totalMirrors;
        }
    }
}
