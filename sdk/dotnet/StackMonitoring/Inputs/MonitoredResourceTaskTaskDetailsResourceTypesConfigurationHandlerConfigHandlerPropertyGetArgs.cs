// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Property name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Property value.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyGetArgs()
        {
        }
        public static new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyGetArgs Empty => new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyGetArgs();
    }
}
