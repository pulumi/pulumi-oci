// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MetricExtensionEnabledOnResourceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the resource on which Metric Extension is enabled
        /// </summary>
        [Input("resourceId")]
        public Input<string>? ResourceId { get; set; }

        public MetricExtensionEnabledOnResourceArgs()
        {
        }
        public static new MetricExtensionEnabledOnResourceArgs Empty => new MetricExtensionEnabledOnResourceArgs();
    }
}
