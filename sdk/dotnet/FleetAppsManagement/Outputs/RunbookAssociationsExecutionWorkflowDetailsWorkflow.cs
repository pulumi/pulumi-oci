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
    public sealed class RunbookAssociationsExecutionWorkflowDetailsWorkflow
    {
        /// <summary>
        /// (Updatable) Name of the group.
        /// </summary>
        public readonly string GroupName;
        /// <summary>
        /// (Updatable) Steps within the Group.
        /// </summary>
        public readonly ImmutableArray<Outputs.RunbookAssociationsExecutionWorkflowDetailsWorkflowStep> Steps;
        /// <summary>
        /// (Updatable) Workflow Group  Details.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private RunbookAssociationsExecutionWorkflowDetailsWorkflow(
            string groupName,

            ImmutableArray<Outputs.RunbookAssociationsExecutionWorkflowDetailsWorkflowStep> steps,

            string type)
        {
            GroupName = groupName;
            Steps = steps;
            Type = type;
        }
    }
}
