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
    public sealed class RunbookRunbookVersionRollbackWorkflowDetailsWorkflowStep
    {
        /// <summary>
        /// Name of the group.
        /// </summary>
        public readonly string? GroupName;
        /// <summary>
        /// Provide StepName for the Task.
        /// </summary>
        public readonly string? StepName;
        /// <summary>
        /// Tasks within the Group. Provide the stepName for all applicable tasks.
        /// </summary>
        public readonly ImmutableArray<string> Steps;
        /// <summary>
        /// Content Source Details.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private RunbookRunbookVersionRollbackWorkflowDetailsWorkflowStep(
            string? groupName,

            string? stepName,

            ImmutableArray<string> steps,

            string type)
        {
            GroupName = groupName;
            StepName = stepName;
            Steps = steps;
            Type = type;
        }
    }
}
