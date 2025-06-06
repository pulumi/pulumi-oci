// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Inputs
{

    public sealed class TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. By default, it is false if not specified.
        /// </summary>
        [Input("preserveBootVolume")]
        public Input<bool>? PreserveBootVolume { get; set; }

        /// <summary>
        /// (Updatable) The type of target asset.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionGetArgs()
        {
        }
        public static new TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionGetArgs Empty => new TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionGetArgs();
    }
}
