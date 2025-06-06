// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetDeployPipelineDeployPipelineEnvironmentItemResult
    {
        /// <summary>
        /// The OCID of an Environment
        /// </summary>
        public readonly string DeployEnvironmentId;
        /// <summary>
        /// List of stages.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageResult> DeployPipelineStages;
        /// <summary>
        /// Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;

        [OutputConstructor]
        private GetDeployPipelineDeployPipelineEnvironmentItemResult(
            string deployEnvironmentId,

            ImmutableArray<Outputs.GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageResult> deployPipelineStages,

            string displayName)
        {
            DeployEnvironmentId = deployEnvironmentId;
            DeployPipelineStages = deployPipelineStages;
            DisplayName = displayName;
        }
    }
}
