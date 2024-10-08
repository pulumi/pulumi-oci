// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class VolumeSourceDetailsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the block volume replica.
        /// </summary>
        [Input("id", required: true)]
        public Input<string> Id { get; set; } = null!;

        /// <summary>
        /// The type can be one of these values: `blockVolumeReplica`, `volume`, `volumeBackup`
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public VolumeSourceDetailsArgs()
        {
        }
        public static new VolumeSourceDetailsArgs Empty => new VolumeSourceDetailsArgs();
    }
}
