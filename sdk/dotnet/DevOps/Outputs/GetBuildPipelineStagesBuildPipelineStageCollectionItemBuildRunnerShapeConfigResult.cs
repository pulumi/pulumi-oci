// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildRunnerShapeConfigResult
    {
        /// <summary>
        /// Name of the build runner shape in which the execution occurs. If not specified, the default shape is chosen.
        /// </summary>
        public readonly string BuildRunnerType;
        /// <summary>
        /// The total amount of memory set for the instance in gigabytes.
        /// </summary>
        public readonly int MemoryInGbs;
        /// <summary>
        /// The total number of OCPUs set for the instance.
        /// </summary>
        public readonly int Ocpus;

        [OutputConstructor]
        private GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildRunnerShapeConfigResult(
            string buildRunnerType,

            int memoryInGbs,

            int ocpus)
        {
            BuildRunnerType = buildRunnerType;
            MemoryInGbs = memoryInGbs;
            Ocpus = ocpus;
        }
    }
}