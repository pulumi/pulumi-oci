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
    public sealed class GetManagedDatabaseOptimizerStatisticsCollectionOperationTaskResult
    {
        /// <summary>
        /// The status of the Optimizer Statistics Collection task.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The name of the target object for which statistics are gathered.
        /// </summary>
        public readonly string Target;
        /// <summary>
        /// The type of target object.
        /// </summary>
        public readonly string TargetType;
        /// <summary>
        /// The end time of the Optimizer Statistics Collection task.
        /// </summary>
        public readonly string TimeEnd;
        /// <summary>
        /// The start time of the Optimizer Statistics Collection task.
        /// </summary>
        public readonly string TimeStart;

        [OutputConstructor]
        private GetManagedDatabaseOptimizerStatisticsCollectionOperationTaskResult(
            string status,

            string target,

            string targetType,

            string timeEnd,

            string timeStart)
        {
            Status = status;
            Target = target;
            TargetType = targetType;
            TimeEnd = timeEnd;
            TimeStart = timeStart;
        }
    }
}