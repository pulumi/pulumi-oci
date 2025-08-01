// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Outputs
{

    [OutputType]
    public sealed class AgentAgentEndpointGuardrailConfigContentModerationConfig
    {
        /// <summary>
        /// (Updatable) An input guardrail mode for content moderation.
        /// </summary>
        public readonly string? InputGuardrailMode;
        /// <summary>
        /// (Updatable) An output guardrail mode for content moderation.
        /// </summary>
        public readonly string? OutputGuardrailMode;

        [OutputConstructor]
        private AgentAgentEndpointGuardrailConfigContentModerationConfig(
            string? inputGuardrailMode,

            string? outputGuardrailMode)
        {
            InputGuardrailMode = inputGuardrailMode;
            OutputGuardrailMode = outputGuardrailMode;
        }
    }
}
