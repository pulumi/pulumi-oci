// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeploymentDeployArtifactOverrideArgumentsItemGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the artifact to which this parameter applies.
        /// </summary>
        [Input("deployArtifactId")]
        public Input<string>? DeployArtifactId { get; set; }

        /// <summary>
        /// Name of the parameter (case-sensitive).
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Value of the parameter.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DeploymentDeployArtifactOverrideArgumentsItemGetArgs()
        {
        }
        public static new DeploymentDeployArtifactOverrideArgumentsItemGetArgs Empty => new DeploymentDeployArtifactOverrideArgumentsItemGetArgs();
    }
}
