// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Inputs
{

    public sealed class RecommendationSupportedLevelGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.RecommendationSupportedLevelItemGetArgs>? _items;

        /// <summary>
        /// The list of supported levels.
        /// </summary>
        public InputList<Inputs.RecommendationSupportedLevelItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.RecommendationSupportedLevelItemGetArgs>());
            set => _items = value;
        }

        public RecommendationSupportedLevelGetArgs()
        {
        }
        public static new RecommendationSupportedLevelGetArgs Empty => new RecommendationSupportedLevelGetArgs();
    }
}
