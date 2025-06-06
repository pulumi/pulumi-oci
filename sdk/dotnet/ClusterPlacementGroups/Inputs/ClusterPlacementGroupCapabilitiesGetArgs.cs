// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ClusterPlacementGroups.Inputs
{

    public sealed class ClusterPlacementGroupCapabilitiesGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("items", required: true)]
        private InputList<Inputs.ClusterPlacementGroupCapabilitiesItemGetArgs>? _items;

        /// <summary>
        /// The supported resources.
        /// </summary>
        public InputList<Inputs.ClusterPlacementGroupCapabilitiesItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.ClusterPlacementGroupCapabilitiesItemGetArgs>());
            set => _items = value;
        }

        public ClusterPlacementGroupCapabilitiesGetArgs()
        {
        }
        public static new ClusterPlacementGroupCapabilitiesGetArgs Empty => new ClusterPlacementGroupCapabilitiesGetArgs();
    }
}
