// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetJobRunsJobRunLogDetailResult
    {
        /// <summary>
        /// The log group id for where log objects will be for job runs.
        /// </summary>
        public readonly string LogGroupId;
        /// <summary>
        /// The log id of the log object the job run logs will be shipped to.
        /// </summary>
        public readonly string LogId;

        [OutputConstructor]
        private GetJobRunsJobRunLogDetailResult(
            string logGroupId,

            string logId)
        {
            LogGroupId = logGroupId;
            LogId = logId;
        }
    }
}
