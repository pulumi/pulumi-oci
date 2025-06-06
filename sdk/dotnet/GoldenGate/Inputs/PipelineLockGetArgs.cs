// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Inputs
{

    public sealed class PipelineLockGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        /// </summary>
        [Input("message")]
        public Input<string>? Message { get; set; }

        /// <summary>
        /// Type of the lock.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public PipelineLockGetArgs()
        {
        }
        public static new PipelineLockGetArgs Empty => new PipelineLockGetArgs();
    }
}
