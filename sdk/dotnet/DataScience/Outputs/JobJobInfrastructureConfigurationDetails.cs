// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class JobJobInfrastructureConfigurationDetails
    {
        /// <summary>
        /// (Updatable) The size of the block storage volume to attach to the instance running the job
        /// </summary>
        public readonly int BlockStorageSizeInGbs;
        /// <summary>
        /// (Updatable) The infrastructure type used for job run.
        /// </summary>
        public readonly string JobInfrastructureType;
        /// <summary>
        /// (Updatable) Details for the job run shape configuration. Specify only when a flex shape is selected.
        /// </summary>
        public readonly Outputs.JobJobInfrastructureConfigurationDetailsJobShapeConfigDetails? JobShapeConfigDetails;
        /// <summary>
        /// (Updatable) The shape used to launch the job run instances.
        /// </summary>
        public readonly string ShapeName;
        /// <summary>
        /// (Updatable) The subnet to create a secondary vnic in to attach to the instance running the job
        /// </summary>
        public readonly string? SubnetId;

        [OutputConstructor]
        private JobJobInfrastructureConfigurationDetails(
            int blockStorageSizeInGbs,

            string jobInfrastructureType,

            Outputs.JobJobInfrastructureConfigurationDetailsJobShapeConfigDetails? jobShapeConfigDetails,

            string shapeName,

            string? subnetId)
        {
            BlockStorageSizeInGbs = blockStorageSizeInGbs;
            JobInfrastructureType = jobInfrastructureType;
            JobShapeConfigDetails = jobShapeConfigDetails;
            ShapeName = shapeName;
            SubnetId = subnetId;
        }
    }
}