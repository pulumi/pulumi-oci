// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Inputs
{

    public sealed class EventDataAdditionalDetailVmcoreGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Kernel vmcore backtrace.
        /// </summary>
        [Input("backtrace")]
        public Input<string>? Backtrace { get; set; }

        /// <summary>
        /// Kernel vmcore component.
        /// </summary>
        [Input("component")]
        public Input<string>? Component { get; set; }

        public EventDataAdditionalDetailVmcoreGetArgs()
        {
        }
        public static new EventDataAdditionalDetailVmcoreGetArgs Empty => new EventDataAdditionalDetailVmcoreGetArgs();
    }
}
