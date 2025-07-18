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
    public sealed class RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariables
    {
        /// <summary>
        /// (Updatable) The input variables for the
        /// task.
        /// </summary>
        public readonly ImmutableArray<Outputs.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable> InputVariables;
        /// <summary>
        /// (Updatable) The list of output variables.
        /// </summary>
        public readonly ImmutableArray<string> OutputVariables;

        [OutputConstructor]
        private RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariables(
            ImmutableArray<Outputs.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable> inputVariables,

            ImmutableArray<string> outputVariables)
        {
            InputVariables = inputVariables;
            OutputVariables = outputVariables;
        }
    }
}
