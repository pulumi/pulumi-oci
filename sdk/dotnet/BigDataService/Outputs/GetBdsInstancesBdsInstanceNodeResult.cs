// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstancesBdsInstanceNodeResult
    {
        /// <summary>
        /// The list of block volumes attached to a given node.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstancesBdsInstanceNodeAttachedBlockVolumeResult> AttachedBlockVolumes;
        /// <summary>
        /// The name of the availability domain in which the node is running.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The name of the fault domain in which the node is running.
        /// </summary>
        public readonly string FaultDomain;
        /// <summary>
        /// The fully-qualified hostname (FQDN) of the node.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The OCID of the image from which the node was created.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// The OCID of the underlying Oracle Cloud Infrastructure Compute instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// IP address of the node.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// Indicates if the node requires a reboot to either reflect the latest os kernel or take actions for maintenance reboot.
        /// </summary>
        public readonly bool IsRebootRequired;
        /// <summary>
        /// The aggregate size of all local disks, in gigabytes. If the instance does not have any local disks, this field is null.
        /// </summary>
        public readonly double LocalDisksTotalSizeInGbs;
        /// <summary>
        /// The total amount of memory available to the node, in gigabytes.
        /// </summary>
        public readonly int MemoryInGbs;
        /// <summary>
        /// Cluster node type.
        /// </summary>
        public readonly string NodeType;
        /// <summary>
        /// The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
        /// </summary>
        public readonly int Nvmes;
        /// <summary>
        /// The total number of OCPUs available to the node.
        /// </summary>
        public readonly int Ocpus;
        /// <summary>
        /// Version of the ODH (Oracle Distribution including Apache Hadoop) for the node.
        /// </summary>
        public readonly string OdhVersion;
        /// <summary>
        /// BDS-assigned Operating System version for the node.
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// Shape of the node.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The fingerprint of the SSH key used for node access.
        /// </summary>
        public readonly string SshFingerprint;
        /// <summary>
        /// The state of the cluster.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of the subnet in which the node is to be created.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the instance is expected to be stopped / started, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeMaintenanceRebootDue;

        [OutputConstructor]
        private GetBdsInstancesBdsInstanceNodeResult(
            ImmutableArray<Outputs.GetBdsInstancesBdsInstanceNodeAttachedBlockVolumeResult> attachedBlockVolumes,

            string availabilityDomain,

            string displayName,

            string faultDomain,

            string hostname,

            string imageId,

            string instanceId,

            string ipAddress,

            bool isRebootRequired,

            double localDisksTotalSizeInGbs,

            int memoryInGbs,

            string nodeType,

            int nvmes,

            int ocpus,

            string odhVersion,

            string osVersion,

            string shape,

            string sshFingerprint,

            string state,

            string subnetId,

            string timeCreated,

            string timeMaintenanceRebootDue)
        {
            AttachedBlockVolumes = attachedBlockVolumes;
            AvailabilityDomain = availabilityDomain;
            DisplayName = displayName;
            FaultDomain = faultDomain;
            Hostname = hostname;
            ImageId = imageId;
            InstanceId = instanceId;
            IpAddress = ipAddress;
            IsRebootRequired = isRebootRequired;
            LocalDisksTotalSizeInGbs = localDisksTotalSizeInGbs;
            MemoryInGbs = memoryInGbs;
            NodeType = nodeType;
            Nvmes = nvmes;
            Ocpus = ocpus;
            OdhVersion = odhVersion;
            OsVersion = osVersion;
            Shape = shape;
            SshFingerprint = sshFingerprint;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeMaintenanceRebootDue = timeMaintenanceRebootDue;
        }
    }
}
