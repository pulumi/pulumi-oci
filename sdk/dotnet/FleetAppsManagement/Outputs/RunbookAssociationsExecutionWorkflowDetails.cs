// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class RunbookAssociationsExecutionWorkflowDetails
    {
        /// <summary>
        /// (Updatable) Execution Workflow for the runbook.
        /// </summary>
        public readonly ImmutableArray<Outputs.RunbookAssociationsExecutionWorkflowDetailsWorkflow> Workflows;

        [OutputConstructor]
        private RunbookAssociationsExecutionWorkflowDetails(ImmutableArray<Outputs.RunbookAssociationsExecutionWorkflowDetailsWorkflow> workflows)
        {
            Workflows = workflows;
        }
    }
}
