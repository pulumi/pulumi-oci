// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployPipelineDeployPipelineArtifactArgs : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeployPipelineDeployPipelineArtifactItemArgs>? _items;

        /// <summary>
        /// (Updatable) List of parameters defined for a deployment pipeline.
        /// </summary>
        public InputList<Inputs.DeployPipelineDeployPipelineArtifactItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeployPipelineDeployPipelineArtifactItemArgs>());
            set => _items = value;
        }

        public DeployPipelineDeployPipelineArtifactArgs()
        {
        }
        public static new DeployPipelineDeployPipelineArtifactArgs Empty => new DeployPipelineDeployPipelineArtifactArgs();
    }
}