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
    public sealed class GetExadataInfrastructureUnAllocatedResourceAutonomousVmClusterResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Total unallocated autonomous data storage in the AVM in TBs.
        /// </summary>
        public readonly double UnAllocatedAdbStorageInTbs;

        [OutputConstructor]
        private GetExadataInfrastructureUnAllocatedResourceAutonomousVmClusterResult(
            string id,

            double unAllocatedAdbStorageInTbs)
        {
            Id = id;
            UnAllocatedAdbStorageInTbs = unAllocatedAdbStorageInTbs;
        }
    }
}