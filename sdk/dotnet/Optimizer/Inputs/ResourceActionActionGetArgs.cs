// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Inputs
{

    public sealed class ResourceActionActionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Text describing the recommended action.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The status of the resource action.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// The URL path to documentation that explains how to perform the action.
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        public ResourceActionActionGetArgs()
        {
        }
        public static new ResourceActionActionGetArgs Empty => new ResourceActionActionGetArgs();
    }
}
