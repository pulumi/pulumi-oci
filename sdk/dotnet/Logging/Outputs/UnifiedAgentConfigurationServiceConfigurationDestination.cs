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
    public sealed class UnifiedAgentConfigurationServiceConfigurationDestination
    {
        /// <summary>
        /// (Updatable) The OCID of the resource.
        /// </summary>
        public readonly string LogObjectId;
        /// <summary>
        /// (Updatable) Unified monitoring agent operational metrics configuration object.
        /// </summary>
        public readonly Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfiguration? OperationalMetricsConfiguration;

        [OutputConstructor]
        private UnifiedAgentConfigurationServiceConfigurationDestination(
            string logObjectId,

            Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfiguration? operationalMetricsConfiguration)
        {
            LogObjectId = logObjectId;
            OperationalMetricsConfiguration = operationalMetricsConfiguration;
        }
    }
}
