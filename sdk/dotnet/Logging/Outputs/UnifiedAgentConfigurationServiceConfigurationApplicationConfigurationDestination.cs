// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationDestination
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that the resource belongs to.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// (Updatable) Namespace to which metrics will be emitted.
        /// </summary>
        public readonly string? MetricsNamespace;

        [OutputConstructor]
        private UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationDestination(
            string? compartmentId,

            string? metricsNamespace)
        {
            CompartmentId = compartmentId;
            MetricsNamespace = metricsNamespace;
        }
    }
}
