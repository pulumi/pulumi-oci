// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetCloudAutonomousVmClustersCloudAutonomousVmClusterResult
    {
        /// <summary>
        /// A filter to return only resources that match the given availability domain exactly.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// If provided, filters the results for the specified cloud Exadata infrastructure.
        /// </summary>
        public readonly string CloudExadataInfrastructureId;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The number of CPU cores enabled on the cloud Autonomous VM cluster.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// The total data storage allocated, in gigabytes (GB).
        /// </summary>
        public readonly double DataStorageSizeInGb;
        /// <summary>
        /// The total data storage allocated, in terabytes (TB).
        /// </summary>
        public readonly double DataStorageSizeInTbs;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// User defined description of the cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The domain name for the cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The hostname for the cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        /// </summary>
        public readonly string LastMaintenanceRunId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history. This value is updated when a maintenance update starts.
        /// </summary>
        public readonly string LastUpdateHistoryEntryId;
        /// <summary>
        /// The Oracle license model that applies to the Oracle Autonomous Database. Bring your own license (BYOL) allows you to apply your current on-premises Oracle software licenses to equivalent, highly automated Oracle PaaS and IaaS services in the cloud. License Included allows you to subscribe to new Oracle Database software licenses and the Database service. Note that when provisioning an Autonomous Database on [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), this attribute must be null because the attribute is already set at the Autonomous Exadata Infrastructure level. When using [shared Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html), if a value is not specified, the system will supply the value of `BRING_YOUR_OWN_LICENSE`.
        /// </summary>
        public readonly string LicenseModel;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The memory allocated in GBs.
        /// </summary>
        public readonly int MemorySizeInGbs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        /// </summary>
        public readonly string NextMaintenanceRunId;
        /// <summary>
        /// The number of database servers in the cloud VM cluster.
        /// </summary>
        public readonly int NodeCount;
        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
        /// * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The number of CPU cores enabled on the cloud Autonomous VM cluster. Only 1 decimal place is allowed for the fractional part.
        /// </summary>
        public readonly double OcpuCount;
        public readonly bool RotateOrdsCertsTrigger;
        public readonly bool RotateSslCertsTrigger;
        /// <summary>
        /// The model name of the Exadata hardware running the cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the cloud Autonomous VM Cluster is associated with.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time that the cloud Autonomous VM cluster was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last date and time that the cloud Autonomous VM cluster was updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetCloudAutonomousVmClustersCloudAutonomousVmClusterResult(
            string availabilityDomain,

            string cloudExadataInfrastructureId,

            string compartmentId,

            int cpuCoreCount,

            double dataStorageSizeInGb,

            double dataStorageSizeInTbs,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string domain,

            ImmutableDictionary<string, object> freeformTags,

            string hostname,

            string id,

            string lastMaintenanceRunId,

            string lastUpdateHistoryEntryId,

            string licenseModel,

            string lifecycleDetails,

            int memorySizeInGbs,

            string nextMaintenanceRunId,

            int nodeCount,

            ImmutableArray<string> nsgIds,

            double ocpuCount,

            bool rotateOrdsCertsTrigger,

            bool rotateSslCertsTrigger,

            string shape,

            string state,

            string subnetId,

            string timeCreated,

            string timeUpdated)
        {
            AvailabilityDomain = availabilityDomain;
            CloudExadataInfrastructureId = cloudExadataInfrastructureId;
            CompartmentId = compartmentId;
            CpuCoreCount = cpuCoreCount;
            DataStorageSizeInGb = dataStorageSizeInGb;
            DataStorageSizeInTbs = dataStorageSizeInTbs;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            Domain = domain;
            FreeformTags = freeformTags;
            Hostname = hostname;
            Id = id;
            LastMaintenanceRunId = lastMaintenanceRunId;
            LastUpdateHistoryEntryId = lastUpdateHistoryEntryId;
            LicenseModel = licenseModel;
            LifecycleDetails = lifecycleDetails;
            MemorySizeInGbs = memorySizeInGbs;
            NextMaintenanceRunId = nextMaintenanceRunId;
            NodeCount = nodeCount;
            NsgIds = nsgIds;
            OcpuCount = ocpuCount;
            RotateOrdsCertsTrigger = rotateOrdsCertsTrigger;
            RotateSslCertsTrigger = rotateSslCertsTrigger;
            Shape = shape;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
