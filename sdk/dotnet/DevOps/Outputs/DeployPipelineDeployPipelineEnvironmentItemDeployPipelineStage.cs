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
    public sealed class DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage
    {
        /// <summary>
        /// (Updatable) List of parameters defined for a deployment pipeline.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageItem> Items;

        [OutputConstructor]
        private DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage(ImmutableArray<Outputs.DeployPipelineDeployPipelineEnvironmentItemDeployPipelineStageItem> items)
        {
            Items = items;
        }
    }
}