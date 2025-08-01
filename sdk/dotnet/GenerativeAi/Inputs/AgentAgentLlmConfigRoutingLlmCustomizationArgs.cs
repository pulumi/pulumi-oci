// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentAgentLlmConfigRoutingLlmCustomizationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) If specified, the default instruction is replaced with provided instruction.
        /// </summary>
        [Input("instruction")]
        public Input<string>? Instruction { get; set; }

        public AgentAgentLlmConfigRoutingLlmCustomizationArgs()
        {
        }
        public static new AgentAgentLlmConfigRoutingLlmCustomizationArgs Empty => new AgentAgentLlmConfigRoutingLlmCustomizationArgs();
    }
}
