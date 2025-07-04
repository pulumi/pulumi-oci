// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class RunbookRunbookVersionRollbackWorkflowDetailsWorkflowArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of the group.
        /// </summary>
        [Input("groupName", required: true)]
        public Input<string> GroupName { get; set; } = null!;

        [Input("steps", required: true)]
        private InputList<Inputs.RunbookRunbookVersionRollbackWorkflowDetailsWorkflowStepArgs>? _steps;

        /// <summary>
        /// Steps within the Group.
        /// </summary>
        public InputList<Inputs.RunbookRunbookVersionRollbackWorkflowDetailsWorkflowStepArgs> Steps
        {
            get => _steps ?? (_steps = new InputList<Inputs.RunbookRunbookVersionRollbackWorkflowDetailsWorkflowStepArgs>());
            set => _steps = value;
        }

        /// <summary>
        /// Workflow Group  Details.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public RunbookRunbookVersionRollbackWorkflowDetailsWorkflowArgs()
        {
        }
        public static new RunbookRunbookVersionRollbackWorkflowDetailsWorkflowArgs Empty => new RunbookRunbookVersionRollbackWorkflowDetailsWorkflowArgs();
    }
}
