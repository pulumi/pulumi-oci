// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MetricExtensionQueryPropertiesSqlDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Sql statement or script file content as base64 encoded string
        /// </summary>
        [Input("content", required: true)]
        public Input<string> Content { get; set; } = null!;

        /// <summary>
        /// (Updatable) If a script needs to be executed, then provide file name of the script
        /// </summary>
        [Input("scriptFileName")]
        public Input<string>? ScriptFileName { get; set; }

        public MetricExtensionQueryPropertiesSqlDetailsGetArgs()
        {
        }
        public static new MetricExtensionQueryPropertiesSqlDetailsGetArgs Empty => new MetricExtensionQueryPropertiesSqlDetailsGetArgs();
    }
}