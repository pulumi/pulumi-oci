// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterOptionsAddOnsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether or not to enable the Kubernetes Dashboard add-on.
        /// </summary>
        [Input("isKubernetesDashboardEnabled")]
        public Input<bool>? IsKubernetesDashboardEnabled { get; set; }

        /// <summary>
        /// Whether or not to enable the Tiller add-on.
        /// </summary>
        [Input("isTillerEnabled")]
        public Input<bool>? IsTillerEnabled { get; set; }

        public ClusterOptionsAddOnsGetArgs()
        {
        }
        public static new ClusterOptionsAddOnsGetArgs Empty => new ClusterOptionsAddOnsGetArgs();
    }
}
