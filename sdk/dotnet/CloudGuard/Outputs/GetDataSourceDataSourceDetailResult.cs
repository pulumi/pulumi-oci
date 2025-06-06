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
    public sealed class GetDataSourceDataSourceDetailResult
    {
        /// <summary>
        /// The additional entities count used for data source query
        /// </summary>
        public readonly int AdditionalEntitiesCount;
        /// <summary>
        /// Possible type of dataSourceFeed Provider(LoggingQuery)
        /// </summary>
        public readonly string DataSourceFeedProvider;
        /// <summary>
        /// Description text for the query
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Interval in minutes that query is run periodically.
        /// </summary>
        public readonly int IntervalInMinutes;
        /// <summary>
        /// Interval in minutes which query is run periodically.
        /// </summary>
        public readonly int IntervalInSeconds;
        /// <summary>
        /// Details for a logging query for a data source.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceDataSourceDetailLoggingQueryDetailResult> LoggingQueryDetails;
        /// <summary>
        /// Type of logging query for data source (Sighting/Insight)
        /// </summary>
        public readonly string LoggingQueryType;
        /// <summary>
        /// Operator used in data source
        /// </summary>
        public readonly string Operator;
        /// <summary>
        /// The continuous query expression that is run periodically.
        /// </summary>
        public readonly string Query;
        /// <summary>
        /// Time when the query can start. If not specified it can start immediately
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceDataSourceDetailQueryStartTimeResult> QueryStartTimes;
        /// <summary>
        /// List of logging query regions
        /// </summary>
        public readonly ImmutableArray<string> Regions;
        /// <summary>
        /// Target information in which scheduled query will be run
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourceDataSourceDetailScheduledQueryScopeDetailResult> ScheduledQueryScopeDetails;
        /// <summary>
        /// The integer value that must be exceeded, fall below or equal to (depending on the operator), for the query result to trigger an event
        /// </summary>
        public readonly int Threshold;

        [OutputConstructor]
        private GetDataSourceDataSourceDetailResult(
            int additionalEntitiesCount,

            string dataSourceFeedProvider,

            string description,

            int intervalInMinutes,

            int intervalInSeconds,

            ImmutableArray<Outputs.GetDataSourceDataSourceDetailLoggingQueryDetailResult> loggingQueryDetails,

            string loggingQueryType,

            string @operator,

            string query,

            ImmutableArray<Outputs.GetDataSourceDataSourceDetailQueryStartTimeResult> queryStartTimes,

            ImmutableArray<string> regions,

            ImmutableArray<Outputs.GetDataSourceDataSourceDetailScheduledQueryScopeDetailResult> scheduledQueryScopeDetails,

            int threshold)
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
            QueryStartTimes = queryStartTimes;
            Regions = regions;
            ScheduledQueryScopeDetails = scheduledQueryScopeDetails;
            Threshold = threshold;
        }
    }
}
