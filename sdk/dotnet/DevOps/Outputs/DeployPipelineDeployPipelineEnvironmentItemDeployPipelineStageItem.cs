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
    public sealed class DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageItem
    {
        /// <summary>
        /// The OCID of a stage
        /// </summary>
        public readonly string? DeployStageId;
        /// <summary>
        /// (Updatable) Deployment pipeline display name. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;

        [OutputConstructor]
        private DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageItem(
            string? deployStageId,

            string? displayName)
        {
            DeployStageId = deployStageId;
            DisplayName = displayName;
        }
    }
}
