// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Outputs
{

    [OutputType]
    public sealed class TargetAssetTestSpecPreemptibleInstanceConfig
    {
        /// <summary>
        /// (Updatable) The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        public readonly ImmutableArray<Outputs.TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction> PreemptionActions;

        [OutputConstructor]
        private TargetAssetTestSpecPreemptibleInstanceConfig(ImmutableArray<Outputs.TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction> preemptionActions)
        {
            PreemptionActions = preemptionActions;
        }
    }
}