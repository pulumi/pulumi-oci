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
    public sealed class MigrationPlanStrategy
    {
        /// <summary>
        /// (Updatable) The real resource usage is multiplied to this number before making any recommendation.
        /// </summary>
        public readonly double? AdjustmentMultiplier;
        /// <summary>
        /// (Updatable) The current state of the migration plan.
        /// </summary>
        public readonly string? MetricTimeWindow;
        /// <summary>
        /// (Updatable) The current state of the migration plan.
        /// </summary>
        public readonly string? MetricType;
        /// <summary>
        /// (Updatable) Percentile value
        /// </summary>
        public readonly string? Percentile;
        /// <summary>
        /// (Updatable) The type of resource.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// (Updatable) The type of strategy used for migration.
        /// </summary>
        public readonly string StrategyType;

        [OutputConstructor]
        private MigrationPlanStrategy(
            double? adjustmentMultiplier,

            string? metricTimeWindow,

            string? metricType,

            string? percentile,

            string resourceType,

            string strategyType)
        {
            AdjustmentMultiplier = adjustmentMultiplier;
            MetricTimeWindow = metricTimeWindow;
            MetricType = metricType;
            Percentile = percentile;
            ResourceType = resourceType;
            StrategyType = strategyType;
        }
    }
}