// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeploymentDeployPipelineArtifactItemDeployPipelineStageGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeploymentDeployPipelineArtifactItemDeployPipelineStageItemGetArgs>? _items;

        /// <summary>
        /// A list of stage predecessors for a stage.
        /// </summary>
        public InputList<Inputs.DeploymentDeployPipelineArtifactItemDeployPipelineStageItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeploymentDeployPipelineArtifactItemDeployPipelineStageItemGetArgs>());
            set => _items = value;
        }

        public DeploymentDeployPipelineArtifactItemDeployPipelineStageGetArgs()
        {
        }
        public static new DeploymentDeployPipelineArtifactItemDeployPipelineStageGetArgs Empty => new DeploymentDeployPipelineArtifactItemDeployPipelineStageGetArgs();
    }
}
