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
    public sealed class GetRunbookAssociationTaskTaskRecordDetailExecutionDetailResult
    {
        /// <summary>
        /// Optional command to execute the content. You can provide any commands/arguments that can't be part of the script.
        /// </summary>
        public readonly string Command;
        /// <summary>
        /// Content Source details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailContentResult> Contents;
        /// <summary>
        /// Credentials required for executing the task.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailCredentialResult> Credentials;
        /// <summary>
        /// Endpoint to be invoked.
        /// </summary>
        public readonly string Endpoint;
        /// <summary>
        /// The action type of the task
        /// </summary>
        public readonly string ExecutionType;
        /// <summary>
        /// The variable of the task. At least one of the dynamicArguments or output needs to be provided.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailVariableResult> Variables;

        [OutputConstructor]
        private GetRunbookAssociationTaskTaskRecordDetailExecutionDetailResult(
            string command,

            ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailContentResult> contents,

            ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailCredentialResult> credentials,

            string endpoint,

            string executionType,

            ImmutableArray<Outputs.GetRunbookAssociationTaskTaskRecordDetailExecutionDetailVariableResult> variables)
        {
            Command = command;
            Contents = contents;
            Credentials = credentials;
            Endpoint = endpoint;
            ExecutionType = executionType;
            Variables = variables;
        }
    }
}
