// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ClusterPlacementGroups.Inputs
{

    public sealed class ClusterPlacementGroupCapabilitiesItemArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The type of resource.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// The service that the resource is part of.
        /// </summary>
        [Input("service", required: true)]
        public Input<string> Service { get; set; } = null!;

        public ClusterPlacementGroupCapabilitiesItemArgs()
        {
        }
        public static new ClusterPlacementGroupCapabilitiesItemArgs Empty => new ClusterPlacementGroupCapabilitiesItemArgs();
    }
}
