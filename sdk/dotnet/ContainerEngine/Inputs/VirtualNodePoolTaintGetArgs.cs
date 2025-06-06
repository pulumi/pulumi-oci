// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class VirtualNodePoolTaintGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The effect of the pair.
        /// </summary>
        [Input("effect")]
        public Input<string>? Effect { get; set; }

        /// <summary>
        /// (Updatable) The key of the pair.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) The value of the pair.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public VirtualNodePoolTaintGetArgs()
        {
        }
        public static new VirtualNodePoolTaintGetArgs Empty => new VirtualNodePoolTaintGetArgs();
    }
}
