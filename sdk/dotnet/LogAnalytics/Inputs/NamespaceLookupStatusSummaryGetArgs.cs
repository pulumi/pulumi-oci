// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Inputs
{

    public sealed class NamespaceLookupStatusSummaryGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The number of chunks processed.
        /// </summary>
        [Input("chunksProcessed")]
        public Input<string>? ChunksProcessed { get; set; }

        /// <summary>
        /// The failure details, if any.
        /// </summary>
        [Input("failureDetails")]
        public Input<string>? FailureDetails { get; set; }

        /// <summary>
        /// The filename.
        /// </summary>
        [Input("filename")]
        public Input<string>? Filename { get; set; }

        /// <summary>
        /// The status.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// The total number of chunks.
        /// </summary>
        [Input("totalChunks")]
        public Input<string>? TotalChunks { get; set; }

        public NamespaceLookupStatusSummaryGetArgs()
        {
        }
        public static new NamespaceLookupStatusSummaryGetArgs Empty => new NamespaceLookupStatusSummaryGetArgs();
    }
}
