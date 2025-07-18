// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class RunbookRunbookVersionExecutionWorkflowDetailsArgs : global::Pulumi.ResourceArgs
    {
        [Input("workflows", required: true)]
        private InputList<Inputs.RunbookRunbookVersionExecutionWorkflowDetailsWorkflowArgs>? _workflows;

        /// <summary>
        /// Execution Workflow for the runbook.
        /// </summary>
        public InputList<Inputs.RunbookRunbookVersionExecutionWorkflowDetailsWorkflowArgs> Workflows
        {
            get => _workflows ?? (_workflows = new InputList<Inputs.RunbookRunbookVersionExecutionWorkflowDetailsWorkflowArgs>());
            set => _workflows = value;
        }

        public RunbookRunbookVersionExecutionWorkflowDetailsArgs()
        {
        }
        public static new RunbookRunbookVersionExecutionWorkflowDetailsArgs Empty => new RunbookRunbookVersionExecutionWorkflowDetailsArgs();
    }
}
