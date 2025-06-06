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
    public sealed class GetDataSourceEventsDataSourceEventCollectionItemEventInfoResult
    {
        /// <summary>
        /// Possible type of dataSourceFeed Provider (LoggingQuery)
        /// </summary>
        public readonly string DataSourceFeedProvider;
        /// <summary>
        /// Log result details of DataSource for a Problem
        /// </summary>
        public readonly string LogResult;
        /// <summary>
        /// Observed value of DataSource for a Problem
        /// </summary>
        public readonly string ObservedValue;
        /// <summary>
        /// Operator details of DataSource for a Problem
        /// </summary>
        public readonly string Operator;
        /// <summary>
        /// Triggered value of DataSource for a Problem
        /// </summary>
        public readonly string TriggerValue;

        [OutputConstructor]
        private GetDataSourceEventsDataSourceEventCollectionItemEventInfoResult(
            string dataSourceFeedProvider,

            string logResult,

            string observedValue,

            string @operator,

            string triggerValue)
        {
            DataSourceFeedProvider = dataSourceFeedProvider;
            LogResult = logResult;
            ObservedValue = observedValue;
            Operator = @operator;
            TriggerValue = triggerValue;
        }
    }
}
