// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Inputs
{

    public sealed class UnifiedAgentConfigurationServiceConfigurationDestinationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the resource.
        /// </summary>
        [Input("logObjectId", required: true)]
        public Input<string> LogObjectId { get; set; } = null!;

        public UnifiedAgentConfigurationServiceConfigurationDestinationGetArgs()
        {
        }
        public static new UnifiedAgentConfigurationServiceConfigurationDestinationGetArgs Empty => new UnifiedAgentConfigurationServiceConfigurationDestinationGetArgs();
    }
}