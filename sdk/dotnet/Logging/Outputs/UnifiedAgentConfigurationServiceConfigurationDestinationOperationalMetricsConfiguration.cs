// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfiguration
    {
        /// <summary>
        /// (Updatable) Unified monitoring agent operational metrics destination object.
        /// </summary>
        public readonly Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestination Destination;
        /// <summary>
        /// (Updatable) Unified monitoring agent operational metrics source object.
        /// </summary>
        public readonly Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationSource Source;

        [OutputConstructor]
        private UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfiguration(
            Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestination destination,

            Outputs.UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationSource source)
        {
            Destination = destination;
            Source = source;
        }
    }
}