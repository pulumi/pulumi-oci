// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class BuildRunBuildOutputArtifactOverrideParameterItemArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the deployment artifact definition.
        /// </summary>
        [Input("deployArtifactId")]
        public Input<string>? DeployArtifactId { get; set; }

        /// <summary>
        /// Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: 'Build_Pipeline_param' is not same as 'build_pipeline_Param'
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Value of the argument.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public BuildRunBuildOutputArtifactOverrideParameterItemArgs()
        {
        }
        public static new BuildRunBuildOutputArtifactOverrideParameterItemArgs Empty => new BuildRunBuildOutputArtifactOverrideParameterItemArgs();
    }
}