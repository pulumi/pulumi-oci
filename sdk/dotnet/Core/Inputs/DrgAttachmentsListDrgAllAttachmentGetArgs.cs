// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class DrgAttachmentsListDrgAllAttachmentGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The Oracle-assigned ID of the DRG attachment
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public DrgAttachmentsListDrgAllAttachmentGetArgs()
        {
        }
        public static new DrgAttachmentsListDrgAllAttachmentGetArgs Empty => new DrgAttachmentsListDrgAllAttachmentGetArgs();
    }
}
