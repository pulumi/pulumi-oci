// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelFetchErrorFetchErrorResult
    {
        /// <summary>
        /// The error message of the most recent error that caused the I/O thread to stop.
        /// </summary>
        public readonly string LastErrorMessage;
        /// <summary>
        /// The error number of the most recent error that caused the I/O thread to stop.
        /// </summary>
        public readonly int LastErrorNumber;
        /// <summary>
        /// The timestamp when the most recent I/O error occurred.
        /// </summary>
        public readonly string TimeLastError;

        [OutputConstructor]
        private GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionStatusSummaryChannelFetchErrorFetchErrorResult(
            string lastErrorMessage,

            int lastErrorNumber,

            string timeLastError)
        {
            LastErrorMessage = lastErrorMessage;
            LastErrorNumber = lastErrorNumber;
            TimeLastError = timeLastError;
        }
    }
}
