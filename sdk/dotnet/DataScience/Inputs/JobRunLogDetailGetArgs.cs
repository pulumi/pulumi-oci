// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class JobRunLogDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The log group id for where log objects will be for job runs.
        /// </summary>
        [Input("logGroupId")]
        public Input<string>? LogGroupId { get; set; }

        /// <summary>
        /// The log id of the log object the job run logs will be shipped to.
        /// </summary>
        [Input("logId")]
        public Input<string>? LogId { get; set; }

        public JobRunLogDetailGetArgs()
        {
        }
        public static new JobRunLogDetailGetArgs Empty => new JobRunLogDetailGetArgs();
    }
}
