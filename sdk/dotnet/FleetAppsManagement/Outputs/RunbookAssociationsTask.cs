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
    public sealed class RunbookAssociationsTask
    {
        /// <summary>
        /// (Updatable) The association type of the task
        /// </summary>
        public readonly string AssociationType;
        /// <summary>
        /// (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
        /// </summary>
        public readonly ImmutableArray<Outputs.RunbookAssociationsTaskOutputVariableMapping> OutputVariableMappings;
        /// <summary>
        /// (Updatable) The name of the task step.
        /// </summary>
        public readonly string StepName;
        /// <summary>
        /// (Updatable) The properties of the component.
        /// </summary>
        public readonly Outputs.RunbookAssociationsTaskStepProperties? StepProperties;
        /// <summary>
        /// (Updatable) The details of the task.
        /// </summary>
        public readonly Outputs.RunbookAssociationsTaskTaskRecordDetails TaskRecordDetails;

        [OutputConstructor]
        private RunbookAssociationsTask(
            string associationType,

            ImmutableArray<Outputs.RunbookAssociationsTaskOutputVariableMapping> outputVariableMappings,

            string stepName,

            Outputs.RunbookAssociationsTaskStepProperties? stepProperties,

            Outputs.RunbookAssociationsTaskTaskRecordDetails taskRecordDetails)
        {
            AssociationType = associationType;
            OutputVariableMappings = outputVariableMappings;
            StepName = stepName;
            StepProperties = stepProperties;
            TaskRecordDetails = taskRecordDetails;
        }
    }
}
