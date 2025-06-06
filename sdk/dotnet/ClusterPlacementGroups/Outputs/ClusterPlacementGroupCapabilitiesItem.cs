// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ClusterPlacementGroups.Outputs
{

    [OutputType]
    public sealed class ClusterPlacementGroupCapabilitiesItem
    {
        /// <summary>
        /// The type of resource.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The service that the resource is part of.
        /// </summary>
        public readonly string Service;

        [OutputConstructor]
        private ClusterPlacementGroupCapabilitiesItem(
            string name,

            string service)
        {
            Name = name;
            Service = service;
        }
    }
}
