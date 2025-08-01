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
    public sealed class AgentAgentEndpointOutputConfig
    {
        /// <summary>
        /// (Updatable) Location of the output.
        /// </summary>
        public readonly Outputs.AgentAgentEndpointOutputConfigOutputLocation OutputLocation;
        /// <summary>
        /// (Updatable) Retention duration of the output data.
        /// </summary>
        public readonly int? RetentionPeriodInMinutes;

        [OutputConstructor]
        private AgentAgentEndpointOutputConfig(
            Outputs.AgentAgentEndpointOutputConfigOutputLocation outputLocation,

            int? retentionPeriodInMinutes)
        {
            OutputLocation = outputLocation;
            RetentionPeriodInMinutes = retentionPeriodInMinutes;
        }
    }
}
