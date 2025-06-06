// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FusionApps.Inputs
{

    public sealed class FusionEnvironmentFamilyFamilyMaintenancePolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Option to upgrade both production and non-production environments at the same time. When set to PROD both types of environnments are upgraded on the production schedule. When set to NON_PROD both types of environments are upgraded on the non-production schedule.
        /// </summary>
        [Input("concurrentMaintenance")]
        public Input<string>? ConcurrentMaintenance { get; set; }

        /// <summary>
        /// (Updatable) When True, monthly patching is enabled for the environment family.
        /// </summary>
        [Input("isMonthlyPatchingEnabled")]
        public Input<bool>? IsMonthlyPatchingEnabled { get; set; }

        /// <summary>
        /// The quarterly maintenance month group schedule of the Fusion environment family.
        /// </summary>
        [Input("quarterlyUpgradeBeginTimes")]
        public Input<string>? QuarterlyUpgradeBeginTimes { get; set; }

        public FusionEnvironmentFamilyFamilyMaintenancePolicyArgs()
        {
        }
        public static new FusionEnvironmentFamilyFamilyMaintenancePolicyArgs Empty => new FusionEnvironmentFamilyFamilyMaintenancePolicyArgs();
    }
}
