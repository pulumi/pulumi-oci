// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class DiscoveryJobDiscoveryDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of Management Agent
        /// </summary>
        [Input("agentId", required: true)]
        public Input<string> AgentId { get; set; } = null!;

        /// <summary>
        /// List of DiscoveryJob Credential Details.
        /// </summary>
        [Input("credentials")]
        public Input<Inputs.DiscoveryJobDiscoveryDetailsCredentialsGetArgs>? Credentials { get; set; }

        /// <summary>
        /// Property Details
        /// </summary>
        [Input("properties", required: true)]
        public Input<Inputs.DiscoveryJobDiscoveryDetailsPropertiesGetArgs> Properties { get; set; } = null!;

        /// <summary>
        /// The Name of resource type
        /// </summary>
        [Input("resourceName", required: true)]
        public Input<string> ResourceName { get; set; } = null!;

        /// <summary>
        /// Resource Type.
        /// </summary>
        [Input("resourceType", required: true)]
        public Input<string> ResourceType { get; set; } = null!;

        /// <summary>
        /// Property Details
        /// </summary>
        [Input("tags")]
        public Input<Inputs.DiscoveryJobDiscoveryDetailsTagsGetArgs>? Tags { get; set; }

        public DiscoveryJobDiscoveryDetailsGetArgs()
        {
        }
        public static new DiscoveryJobDiscoveryDetailsGetArgs Empty => new DiscoveryJobDiscoveryDetailsGetArgs();
    }
}