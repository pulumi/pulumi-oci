// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Inputs
{

    public sealed class UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestinationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        public UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestinationGetArgs()
        {
        }
        public static new UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestinationGetArgs Empty => new UnifiedAgentConfigurationServiceConfigurationDestinationOperationalMetricsConfigurationDestinationGetArgs();
    }
}