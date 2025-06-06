// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class CloudGuardDataSourceDataSourceDetails
    {
        /// <summary>
        /// (Updatable) The additional entities count used for data source query
        /// </summary>
        public readonly int? AdditionalEntitiesCount;
        /// <summary>
        /// (Updatable) Type of data source feed provider (LoggingQuery)
        /// </summary>
        public readonly string DataSourceFeedProvider;
        /// <summary>
        /// (Updatable) Description text for the query
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Interval in minutes that query is run periodically.
        /// </summary>
        public readonly int? IntervalInMinutes;
        /// <summary>
        /// (Updatable) Interval in minutes which query is run periodically.
        /// </summary>
        public readonly int? IntervalInSeconds;
        /// <summary>
        /// (Updatable) Details for a logging query for a data source.
        /// </summary>
        public readonly Outputs.CloudGuardDataSourceDataSourceDetailsLoggingQueryDetails? LoggingQueryDetails;
        /// <summary>
        /// (Updatable) Type of logging query for data source (Sighting/Insight)
        /// </summary>
        public readonly string? LoggingQueryType;
        /// <summary>
        /// (Updatable) Operator used in data source
        /// </summary>
        public readonly string? Operator;
        /// <summary>
        /// (Updatable) The continuous query expression that is run periodically.
        /// </summary>
        public readonly string? Query;
        /// <summary>
        /// (Updatable) Start policy for continuous query
        /// </summary>
        public readonly Outputs.CloudGuardDataSourceDataSourceDetailsQueryStartTime? QueryStartTime;
        /// <summary>
        /// (Updatable) List of logging query regions
        /// </summary>
        public readonly ImmutableArray<string> Regions;
        /// <summary>
        /// (Updatable) Target information in which scheduled query will be run
        /// </summary>
        public readonly ImmutableArray<Outputs.CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetail> ScheduledQueryScopeDetails;
        /// <summary>
        /// (Updatable) The integer value that must be exceeded, fall below or equal to (depending on the operator), for the query result to trigger an event
        /// </summary>
        public readonly int? Threshold;

        [OutputConstructor]
        private CloudGuardDataSourceDataSourceDetails(
            int? additionalEntitiesCount,

            string dataSourceFeedProvider,

            string? description,

            int? intervalInMinutes,

            int? intervalInSeconds,

            Outputs.CloudGuardDataSourceDataSourceDetailsLoggingQueryDetails? loggingQueryDetails,

            string? loggingQueryType,

            string? @operator,

            string? query,

            Outputs.CloudGuardDataSourceDataSourceDetailsQueryStartTime? queryStartTime,

            ImmutableArray<string> regions,

            ImmutableArray<Outputs.CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetail> scheduledQueryScopeDetails,

            int? threshold)
        {
            AdditionalEntitiesCount = additionalEntitiesCount;
            DataSourceFeedProvider = dataSourceFeedProvider;
            Description = description;
            IntervalInMinutes = intervalInMinutes;
            IntervalInSeconds = intervalInSeconds;
            LoggingQueryDetails = loggingQueryDetails;
            LoggingQueryType = loggingQueryType;
            Operator = @operator;
            Query = query;
            QueryStartTime = queryStartTime;
            Regions = regions;
            ScheduledQueryScopeDetails = scheduledQueryScopeDetails;
            Threshold = threshold;
        }
    }
}
