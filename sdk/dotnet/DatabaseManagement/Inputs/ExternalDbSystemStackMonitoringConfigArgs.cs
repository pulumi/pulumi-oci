// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Inputs
{

    public sealed class ExternalDbSystemStackMonitoringConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The status of the associated service.
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        /// <summary>
        /// The associated service-specific inputs in JSON string format, which Database Management can identify.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("metadata")]
        public Input<string>? Metadata { get; set; }

        public ExternalDbSystemStackMonitoringConfigArgs()
        {
        }
        public static new ExternalDbSystemStackMonitoringConfigArgs Empty => new ExternalDbSystemStackMonitoringConfigArgs();
    }
}