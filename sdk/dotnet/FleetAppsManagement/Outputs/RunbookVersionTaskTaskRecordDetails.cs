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
    public sealed class RunbookVersionTaskTaskRecordDetails
    {
        /// <summary>
        /// (Updatable) The description of the task.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Execution details.
        /// </summary>
        public readonly Outputs.RunbookVersionTaskTaskRecordDetailsExecutionDetails? ExecutionDetails;
        /// <summary>
        /// (Updatable) Is this an Apply Subject Task? Ex. Patch
        /// Execution Task
        /// </summary>
        public readonly bool? IsApplySubjectTask;
        /// <summary>
        /// (Updatable) Make a copy of this task in Library
        /// </summary>
        public readonly bool? IsCopyToLibraryEnabled;
        /// <summary>
        /// (Updatable) Is this a discovery output task?
        /// </summary>
        public readonly bool? IsDiscoveryOutputTask;
        /// <summary>
        /// (Updatable) The name of the task
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) The OS for the task.
        /// </summary>
        public readonly string? OsType;
        /// <summary>
        /// (Updatable) The platform of the runbook.
        /// </summary>
        public readonly string? Platform;
        /// <summary>
        /// (Updatable) The properties of the task.
        /// </summary>
        public readonly Outputs.RunbookVersionTaskTaskRecordDetailsProperties? Properties;
        /// <summary>
        /// (Updatable) The scope of the task.
        /// </summary>
        public readonly string Scope;
        /// <summary>
        /// (Updatable) The ID of taskRecord.
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the
        /// new property values
        /// </summary>
        public readonly string? TaskRecordId;

        [OutputConstructor]
        private RunbookVersionTaskTaskRecordDetails(
            string? description,

            Outputs.RunbookVersionTaskTaskRecordDetailsExecutionDetails? executionDetails,

            bool? isApplySubjectTask,

            bool? isCopyToLibraryEnabled,

            bool? isDiscoveryOutputTask,

            string? name,

            string? osType,

            string? platform,

            Outputs.RunbookVersionTaskTaskRecordDetailsProperties? properties,

            string scope,

            string? taskRecordId)
        {
            Description = description;
            ExecutionDetails = executionDetails;
            IsApplySubjectTask = isApplySubjectTask;
            IsCopyToLibraryEnabled = isCopyToLibraryEnabled;
            IsDiscoveryOutputTask = isDiscoveryOutputTask;
            Name = name;
            OsType = osType;
            Platform = platform;
            Properties = properties;
            Scope = scope;
            TaskRecordId = taskRecordId;
        }
    }
}
