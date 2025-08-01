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
    public sealed class GetRunbooksRunbookCollectionItemRunbookVersionTaskOutputVariableMappingResult
    {
        /// <summary>
        /// The name of the task
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The details of the output variable that will be used for mapping.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemRunbookVersionTaskOutputVariableMappingOutputVariableDetailResult> OutputVariableDetails;

        [OutputConstructor]
        private GetRunbooksRunbookCollectionItemRunbookVersionTaskOutputVariableMappingResult(
            string name,

            ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemRunbookVersionTaskOutputVariableMappingOutputVariableDetailResult> outputVariableDetails)
        {
            Name = name;
            OutputVariableDetails = outputVariableDetails;
        }
    }
}
