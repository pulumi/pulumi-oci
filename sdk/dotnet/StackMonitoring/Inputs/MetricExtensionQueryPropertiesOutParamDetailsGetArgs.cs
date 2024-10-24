// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MetricExtensionQueryPropertiesOutParamDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Position of PL/SQL procedure OUT parameter
        /// </summary>
        [Input("outParamPosition", required: true)]
        public Input<int> OutParamPosition { get; set; } = null!;

        /// <summary>
        /// (Updatable) SQL Type of PL/SQL procedure OUT parameter
        /// </summary>
        [Input("outParamType", required: true)]
        public Input<string> OutParamType { get; set; } = null!;

        public MetricExtensionQueryPropertiesOutParamDetailsGetArgs()
        {
        }
        public static new MetricExtensionQueryPropertiesOutParamDetailsGetArgs Empty => new MetricExtensionQueryPropertiesOutParamDetailsGetArgs();
    }
}
