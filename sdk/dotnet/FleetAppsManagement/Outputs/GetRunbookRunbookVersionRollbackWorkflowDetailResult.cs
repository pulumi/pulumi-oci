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
    public sealed class GetRunbookRunbookVersionRollbackWorkflowDetailResult
    {
        /// <summary>
        /// The scope of the task.
        /// </summary>
        public readonly string Scope;
        /// <summary>
        /// Rollback Workflow for the runbook.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbookRunbookVersionRollbackWorkflowDetailWorkflowResult> Workflows;

        [OutputConstructor]
        private GetRunbookRunbookVersionRollbackWorkflowDetailResult(
            string scope,

            ImmutableArray<Outputs.GetRunbookRunbookVersionRollbackWorkflowDetailWorkflowResult> workflows)
        {
            Scope = scope;
            Workflows = workflows;
        }
    }
}
