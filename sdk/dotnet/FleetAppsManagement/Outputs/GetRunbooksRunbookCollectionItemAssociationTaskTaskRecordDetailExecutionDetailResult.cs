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
    public sealed class GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailResult
    {
        /// <summary>
        /// Optional Command to execute the content.
        /// </summary>
        public readonly string Command;
        /// <summary>
        /// Content Source Details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailContentResult> Contents;
        /// <summary>
        /// Endpoint to be invoked.
        /// </summary>
        public readonly string Endpoint;
        /// <summary>
        /// The action type of the task
        /// </summary>
        public readonly string ExecutionType;
        /// <summary>
        /// The variable of the task.Atleast one of dynamicArguments or output needs to be provided.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailVariableResult> Variables;

        [OutputConstructor]
        private GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailResult(
            string command,

            ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailContentResult> contents,

            string endpoint,

            string executionType,

            ImmutableArray<Outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetailVariableResult> variables)
        {
            Command = command;
            Contents = contents;
            Endpoint = endpoint;
            ExecutionType = executionType;
            Variables = variables;
        }
    }
}
