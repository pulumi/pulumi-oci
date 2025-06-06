// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Inputs
{

    public sealed class KeyRestoreFromObjectStoreGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the bucket where key was backed up
        /// </summary>
        [Input("bucket")]
        public Input<string>? Bucket { get; set; }

        /// <summary>
        /// (Updatable) Type of backup to restore from. Values of "BUCKET", "PRE_AUTHENTICATED_REQUEST_URI" are supported
        /// </summary>
        [Input("destination", required: true)]
        public Input<string> Destination { get; set; } = null!;

        /// <summary>
        /// (Updatable) Namespace of the bucket where key was backed up
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        /// <summary>
        /// (Updatable) Object containing the backup
        /// </summary>
        [Input("object")]
        public Input<string>? Object { get; set; }

        /// <summary>
        /// (Updatable) Pre-authenticated-request-uri of the backup
        /// </summary>
        [Input("uri")]
        public Input<string>? Uri { get; set; }

        public KeyRestoreFromObjectStoreGetArgs()
        {
        }
        public static new KeyRestoreFromObjectStoreGetArgs Empty => new KeyRestoreFromObjectStoreGetArgs();
    }
}
