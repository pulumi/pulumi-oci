// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetRunbookVersionsRunbookVersionCollectionItemTaskTaskRecordDetailExecutionDetailVariableResult
    {
        /// <summary>
        /// The input variables for the task.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbookVersionsRunbookVersionCollectionItemTaskTaskRecordDetailExecutionDetailVariableInputVariableResult> InputVariables;
        /// <summary>
        /// The list of output variables.
        /// </summary>
        public readonly ImmutableArray<string> OutputVariables;

        [OutputConstructor]
        private GetRunbookVersionsRunbookVersionCollectionItemTaskTaskRecordDetailExecutionDetailVariableResult(
            ImmutableArray<Outputs.GetRunbookVersionsRunbookVersionCollectionItemTaskTaskRecordDetailExecutionDetailVariableInputVariableResult> inputVariables,

            ImmutableArray<string> outputVariables)
        {
            InputVariables = inputVariables;
            OutputVariables = outputVariables;
        }
    }
}
