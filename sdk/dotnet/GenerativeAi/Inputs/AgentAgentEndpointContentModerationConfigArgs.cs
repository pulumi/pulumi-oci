// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentAgentEndpointContentModerationConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A flag to enable or disable content moderation on input.
        /// </summary>
        [Input("shouldEnableOnInput")]
        public Input<bool>? ShouldEnableOnInput { get; set; }

        /// <summary>
        /// (Updatable) A flag to enable or disable content moderation on output.
        /// </summary>
        [Input("shouldEnableOnOutput")]
        public Input<bool>? ShouldEnableOnOutput { get; set; }

        public AgentAgentEndpointContentModerationConfigArgs()
        {
        }
        public static new AgentAgentEndpointContentModerationConfigArgs Empty => new AgentAgentEndpointContentModerationConfigArgs();
    }
}
