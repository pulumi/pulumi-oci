// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Inputs
{

    public sealed class TargetAssetUserSpecPreemptibleInstanceConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        [Input("preemptionAction", required: true)]
        public Input<Inputs.TargetAssetUserSpecPreemptibleInstanceConfigPreemptionActionArgs> PreemptionAction { get; set; } = null!;

        public TargetAssetUserSpecPreemptibleInstanceConfigArgs()
        {
        }
        public static new TargetAssetUserSpecPreemptibleInstanceConfigArgs Empty => new TargetAssetUserSpecPreemptibleInstanceConfigArgs();
    }
}