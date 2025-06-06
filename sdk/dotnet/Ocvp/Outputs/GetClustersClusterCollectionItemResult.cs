// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterCollectionItemResult
    {
        public readonly int ActualEsxiHostsCount;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
        /// </summary>
        public readonly string CapacityReservationId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment as optional parameter.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The availability domain the ESXi hosts are running in. For Multi-AD Cluster, it is `multi-AD`.  Example: `Uocm:PHX-AD-1`, `multi-AD`
        /// </summary>
        public readonly string ComputeAvailabilityDomain;
        /// <summary>
        /// Datastores used for the Cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterCollectionItemDatastoreResult> Datastores;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The number of ESXi hosts in the Cluster.
        /// </summary>
        public readonly int EsxiHostsCount;
        /// <summary>
        /// In general, this is a specific version of bundled ESXi software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20230701/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
        /// </summary>
        public readonly string EsxiSoftwareVersion;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The billing option selected during Cluster creation. [ListSupportedCommitments](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedCommitmentSummary/ListSupportedCommitments).
        /// </summary>
        public readonly string InitialCommitment;
        /// <summary>
        /// The initial OCPU count of the Cluster's ESXi hosts.
        /// </summary>
        public readonly double InitialHostOcpuCount;
        /// <summary>
        /// The initial compute shape of the Cluster's ESXi hosts. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
        /// </summary>
        public readonly string InitialHostShapeName;
        /// <summary>
        /// A prefix used in the name of each ESXi host and Compute instance in the Cluster. If this isn't set, the Cluster's `displayName` is used as the prefix.
        /// </summary>
        public readonly string InstanceDisplayNamePrefix;
        /// <summary>
        /// Indicates whether shielded instance is enabled at the Cluster level.
        /// </summary>
        public readonly bool IsShieldedInstanceEnabled;
        /// <summary>
        /// The network configurations used by Cluster, including [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet and VLANs.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterCollectionItemNetworkConfigurationResult> NetworkConfigurations;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
        /// </summary>
        public readonly string SddcId;
        /// <summary>
        /// The lifecycle state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the Cluster was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the Cluster was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The vSphere licenses to use when upgrading the Cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterCollectionItemUpgradeLicenseResult> UpgradeLicenses;
        /// <summary>
        /// In general, this is a specific version of bundled VMware software supported by Oracle Cloud VMware Solution (see [ListSupportedVmwareSoftwareVersions](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedVmwareSoftwareVersionSummary/ListSupportedVmwareSoftwareVersions)).
        /// </summary>
        public readonly string VmwareSoftwareVersion;
        /// <summary>
        /// vSphere Cluster types.
        /// </summary>
        public readonly string VsphereType;
        /// <summary>
        /// The links to binary objects needed to upgrade vSphere.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetClustersClusterCollectionItemVsphereUpgradeObjectResult> VsphereUpgradeObjects;
        /// <summary>
        /// The CIDR block for the IP addresses that VMware VMs in the SDDC use to run application workloads.
        /// </summary>
        public readonly string WorkloadNetworkCidr;

        [OutputConstructor]
        private GetClustersClusterCollectionItemResult(
            int actualEsxiHostsCount,

            string capacityReservationId,

            string compartmentId,

            string computeAvailabilityDomain,

            ImmutableArray<Outputs.GetClustersClusterCollectionItemDatastoreResult> datastores,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            int esxiHostsCount,

            string esxiSoftwareVersion,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string initialCommitment,

            double initialHostOcpuCount,

            string initialHostShapeName,

            string instanceDisplayNamePrefix,

            bool isShieldedInstanceEnabled,

            ImmutableArray<Outputs.GetClustersClusterCollectionItemNetworkConfigurationResult> networkConfigurations,

            string sddcId,

            string state,

            string timeCreated,

            string timeUpdated,

            ImmutableArray<Outputs.GetClustersClusterCollectionItemUpgradeLicenseResult> upgradeLicenses,

            string vmwareSoftwareVersion,

            string vsphereType,

            ImmutableArray<Outputs.GetClustersClusterCollectionItemVsphereUpgradeObjectResult> vsphereUpgradeObjects,

            string workloadNetworkCidr)
        {
            ActualEsxiHostsCount = actualEsxiHostsCount;
            CapacityReservationId = capacityReservationId;
            CompartmentId = compartmentId;
            ComputeAvailabilityDomain = computeAvailabilityDomain;
            Datastores = datastores;
            DefinedTags = definedTags;
            DisplayName = displayName;
            EsxiHostsCount = esxiHostsCount;
            EsxiSoftwareVersion = esxiSoftwareVersion;
            FreeformTags = freeformTags;
            Id = id;
            InitialCommitment = initialCommitment;
            InitialHostOcpuCount = initialHostOcpuCount;
            InitialHostShapeName = initialHostShapeName;
            InstanceDisplayNamePrefix = instanceDisplayNamePrefix;
            IsShieldedInstanceEnabled = isShieldedInstanceEnabled;
            NetworkConfigurations = networkConfigurations;
            SddcId = sddcId;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            UpgradeLicenses = upgradeLicenses;
            VmwareSoftwareVersion = vmwareSoftwareVersion;
            VsphereType = vsphereType;
            VsphereUpgradeObjects = vsphereUpgradeObjects;
            WorkloadNetworkCidr = workloadNetworkCidr;
        }
    }
}
