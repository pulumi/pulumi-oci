// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeploymentDeployPipelineEnvironmentItemArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of an Environment
        /// </summary>
        [Input("deployEnvironmentId")]
        public Input<string>? DeployEnvironmentId { get; set; }

        [Input("deployPipelineStages")]
        private InputList<Inputs.DeploymentDeployPipelineEnvironmentItemDeployPipelineStageArgs>? _deployPipelineStages;

        /// <summary>
        /// List of stages.
        /// </summary>
        public InputList<Inputs.DeploymentDeployPipelineEnvironmentItemDeployPipelineStageArgs> DeployPipelineStages
        {
            get => _deployPipelineStages ?? (_deployPipelineStages = new InputList<Inputs.DeploymentDeployPipelineEnvironmentItemDeployPipelineStageArgs>());
            set => _deployPipelineStages = value;
        }

        /// <summary>
        /// (Updatable) Deployment display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        public DeploymentDeployPipelineEnvironmentItemArgs()
        {
        }
        public static new DeploymentDeployPipelineEnvironmentItemArgs Empty => new DeploymentDeployPipelineEnvironmentItemArgs();
    }
}