// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class TaskRecordDetailsExecutionDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("catalogId")]
        public Input<string>? CatalogId { get; set; }

        /// <summary>
        /// (Updatable) Optional command to execute the content. You can provide any commands/arguments that can't be part of the script.
        /// </summary>
        [Input("command")]
        public Input<string>? Command { get; set; }

        /// <summary>
        /// (Updatable) Catalog Id having config file.
        /// </summary>
        [Input("configFile")]
        public Input<string>? ConfigFile { get; set; }

        /// <summary>
        /// (Updatable) Content Source details.
        /// </summary>
        [Input("content")]
        public Input<Inputs.TaskRecordDetailsExecutionDetailsContentGetArgs>? Content { get; set; }

        [Input("credentials")]
        private InputList<Inputs.TaskRecordDetailsExecutionDetailsCredentialGetArgs>? _credentials;

        /// <summary>
        /// (Updatable) Credentials required for executing the task.
        /// </summary>
        public InputList<Inputs.TaskRecordDetailsExecutionDetailsCredentialGetArgs> Credentials
        {
            get => _credentials ?? (_credentials = new InputList<Inputs.TaskRecordDetailsExecutionDetailsCredentialGetArgs>());
            set => _credentials = value;
        }

        /// <summary>
        /// (Updatable) Endpoint to be invoked.
        /// </summary>
        [Input("endpoint")]
        public Input<string>? Endpoint { get; set; }

        /// <summary>
        /// (Updatable) The action type of the task
        /// </summary>
        [Input("executionType", required: true)]
        public Input<string> ExecutionType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Is the Content an executable file?
        /// </summary>
        [Input("isExecutableContent")]
        public Input<bool>? IsExecutableContent { get; set; }

        /// <summary>
        /// (Updatable) Is the script locked to prevent changes directly in Object Storage?
        /// </summary>
        [Input("isLocked")]
        public Input<bool>? IsLocked { get; set; }

        /// <summary>
        /// (Updatable) Is read output variable enabled
        /// </summary>
        [Input("isReadOutputVariableEnabled")]
        public Input<bool>? IsReadOutputVariableEnabled { get; set; }

        /// <summary>
        /// (Updatable) OCID of the compartment to which the resource belongs to.
        /// </summary>
        [Input("targetCompartmentId")]
        public Input<string>? TargetCompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The variable of the task. At least one of the dynamicArguments or output needs to be provided.
        /// </summary>
        [Input("variables")]
        public Input<Inputs.TaskRecordDetailsExecutionDetailsVariablesGetArgs>? Variables { get; set; }

        public TaskRecordDetailsExecutionDetailsGetArgs()
        {
        }
        public static new TaskRecordDetailsExecutionDetailsGetArgs Empty => new TaskRecordDetailsExecutionDetailsGetArgs();
    }
}
