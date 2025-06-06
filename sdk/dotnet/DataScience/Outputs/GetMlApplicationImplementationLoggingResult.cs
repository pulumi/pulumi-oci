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
    public sealed class GetMlApplicationImplementationLoggingResult
    {
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationLoggingAggregatedInstanceViewLogResult> AggregatedInstanceViewLogs;
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationLoggingImplementationLogResult> ImplementationLogs;
        /// <summary>
        /// Log configuration details for particular areas of ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationLoggingTriggerLogResult> TriggerLogs;

        [OutputConstructor]
        private GetMlApplicationImplementationLoggingResult(
            ImmutableArray<Outputs.GetMlApplicationImplementationLoggingAggregatedInstanceViewLogResult> aggregatedInstanceViewLogs,

            ImmutableArray<Outputs.GetMlApplicationImplementationLoggingImplementationLogResult> implementationLogs,

            ImmutableArray<Outputs.GetMlApplicationImplementationLoggingTriggerLogResult> triggerLogs)
        {
            AggregatedInstanceViewLogs = aggregatedInstanceViewLogs;
            ImplementationLogs = implementationLogs;
            TriggerLogs = triggerLogs;
        }
    }
}
