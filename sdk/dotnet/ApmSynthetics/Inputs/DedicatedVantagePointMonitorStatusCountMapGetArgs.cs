// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class DedicatedVantagePointMonitorStatusCountMapGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Number of disabled monitors using the script.
        /// </summary>
        [Input("disabled")]
        public Input<int>? Disabled { get; set; }

        /// <summary>
        /// Number of enabled monitors using the script.
        /// </summary>
        [Input("enabled")]
        public Input<int>? Enabled { get; set; }

        /// <summary>
        /// Number of invalid monitors using the script.
        /// </summary>
        [Input("invalid")]
        public Input<int>? Invalid { get; set; }

        /// <summary>
        /// Total number of monitors using the script.
        /// </summary>
        [Input("total")]
        public Input<int>? Total { get; set; }

        public DedicatedVantagePointMonitorStatusCountMapGetArgs()
        {
        }
        public static new DedicatedVantagePointMonitorStatusCountMapGetArgs Empty => new DedicatedVantagePointMonitorStatusCountMapGetArgs();
    }
}
