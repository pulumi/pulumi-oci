// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalExadataStorageServerOpenAlertHistoryAlertResult
    {
        /// <summary>
        /// The alert message.
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The severity of the alert.
        /// </summary>
        public readonly string Severity;
        /// <summary>
        /// The start time of the alert.
        /// </summary>
        public readonly string TimeStartAt;
        /// <summary>
        /// The type of alert.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetExternalExadataStorageServerOpenAlertHistoryAlertResult(
            string message,

            string severity,

            string timeStartAt,

            string type)
        {
            Message = message;
            Severity = severity;
            TimeStartAt = timeStartAt;
            Type = type;
        }
    }
}