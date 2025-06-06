// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentAgentEndpointSessionConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The session will become inactive after this timeout.
        /// </summary>
        [Input("idleTimeoutInSeconds")]
        public Input<int>? IdleTimeoutInSeconds { get; set; }

        public AgentAgentEndpointSessionConfigArgs()
        {
        }
        public static new AgentAgentEndpointSessionConfigArgs Empty => new AgentAgentEndpointSessionConfigArgs();
    }
}
