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
    public sealed class GetBdsInstancesBdsInstanceCloudSqlDetailResult
    {
        /// <summary>
        /// The size of block volume in GB that needs to be attached to a given node. All the necessary details needed for attachment are managed by service itself.
        /// </summary>
        public readonly string BlockVolumeSizeInGbs;
        /// <summary>
        /// IP address of the node.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// Boolean flag specifying whether or not Kerberos principals are mapped to database users.
        /// </summary>
        public readonly bool IsKerberosMappedToDatabaseUsers;
        /// <summary>
        /// Details about the Kerberos principals.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstancesBdsInstanceCloudSqlDetailKerberosDetailResult> KerberosDetails;
        /// <summary>
        /// The total amount of memory available to the node, in gigabytes.
        /// </summary>
        public readonly int MemoryInGbs;
        /// <summary>
        /// The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
        /// </summary>
        public readonly int Nvmes;
        /// <summary>
        /// The total number of OCPUs available to the node.
        /// </summary>
        public readonly int Ocpus;
        /// <summary>
        /// Shape of the node.
        /// </summary>
        public readonly string Shape;

        [OutputConstructor]
        private GetBdsInstancesBdsInstanceCloudSqlDetailResult(
            string blockVolumeSizeInGbs,

            string ipAddress,

            bool isKerberosMappedToDatabaseUsers,

            ImmutableArray<Outputs.GetBdsInstancesBdsInstanceCloudSqlDetailKerberosDetailResult> kerberosDetails,

            int memoryInGbs,

            int nvmes,

            int ocpus,

            string shape)
        {
            BlockVolumeSizeInGbs = blockVolumeSizeInGbs;
            IpAddress = ipAddress;
            IsKerberosMappedToDatabaseUsers = isKerberosMappedToDatabaseUsers;
            KerberosDetails = kerberosDetails;
            MemoryInGbs = memoryInGbs;
            Nvmes = nvmes;
            Ocpus = ocpus;
            Shape = shape;
        }
    }
}
