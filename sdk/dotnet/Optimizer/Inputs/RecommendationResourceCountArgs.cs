// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Inputs
{

    public sealed class RecommendationResourceCountArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The count of resources.
        /// </summary>
        [Input("count")]
        public Input<int>? Count { get; set; }

        /// <summary>
        /// (Updatable) The status of the recommendation.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        public RecommendationResourceCountArgs()
        {
        }
        public static new RecommendationResourceCountArgs Empty => new RecommendationResourceCountArgs();
    }
}
