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
    public sealed class GetPipelinesPipelineInfrastructureConfigurationDetailResult
    {
        /// <summary>
        /// The size of the block storage volume to attach to the instance.
        /// </summary>
        public readonly int BlockStorageSizeInGbs;
        /// <summary>
        /// Details for the pipeline step run shape configuration. Specify only when a flex shape is selected.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelinesPipelineInfrastructureConfigurationDetailShapeConfigDetailResult> ShapeConfigDetails;
        /// <summary>
        /// The shape used to launch the instance for all step runs in the pipeline.
        /// </summary>
        public readonly string ShapeName;

        [OutputConstructor]
        private GetPipelinesPipelineInfrastructureConfigurationDetailResult(
            int blockStorageSizeInGbs,

            ImmutableArray<Outputs.GetPipelinesPipelineInfrastructureConfigurationDetailShapeConfigDetailResult> shapeConfigDetails,

            string shapeName)
        {
            BlockStorageSizeInGbs = blockStorageSizeInGbs;
            ShapeConfigDetails = shapeConfigDetails;
            ShapeName = shapeName;
        }
    }
}