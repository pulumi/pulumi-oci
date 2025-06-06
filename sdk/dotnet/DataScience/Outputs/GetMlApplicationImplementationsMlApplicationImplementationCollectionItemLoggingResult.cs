// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingResult
    {
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingAggregatedInstanceViewLogResult> AggregatedInstanceViewLogs;
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingImplementationLogResult> ImplementationLogs;
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingTriggerLogResult> TriggerLogs;

        [OutputConstructor]
        private GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingResult(
            ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingAggregatedInstanceViewLogResult> aggregatedInstanceViewLogs,

            ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingImplementationLogResult> implementationLogs,

            ImmutableArray<Outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItemLoggingTriggerLogResult> triggerLogs)
        {
            AggregatedInstanceViewLogs = aggregatedInstanceViewLogs;
            ImplementationLogs = implementationLogs;
            TriggerLogs = triggerLogs;
        }
    }
}
