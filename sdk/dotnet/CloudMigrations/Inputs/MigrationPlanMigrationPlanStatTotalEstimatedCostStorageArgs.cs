// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Inputs
{

    public sealed class MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Gigabyte storage capacity per month.
        /// </summary>
        [Input("totalGbPerMonth")]
        public Input<double>? TotalGbPerMonth { get; set; }

        /// <summary>
        /// Gigabyte storage capacity per month by subscription
        /// </summary>
        [Input("totalGbPerMonthBySubscription")]
        public Input<double>? TotalGbPerMonthBySubscription { get; set; }

        [Input("volumes")]
        private InputList<Inputs.MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs>? _volumes;

        /// <summary>
        /// Volume estimation
        /// </summary>
        public InputList<Inputs.MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs> Volumes
        {
            get => _volumes ?? (_volumes = new InputList<Inputs.MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs>());
            set => _volumes = value;
        }

        public MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs()
        {
        }
        public static new MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs Empty => new MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs();
    }
}
