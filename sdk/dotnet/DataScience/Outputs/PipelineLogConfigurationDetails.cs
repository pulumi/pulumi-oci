// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class PipelineLogConfigurationDetails
    {
        /// <summary>
        /// (Updatable) If automatic on-behalf-of log object creation is enabled for pipeline runs.
        /// </summary>
        public readonly bool? EnableAutoLogCreation;
        /// <summary>
        /// (Updatable) If customer logging is enabled for pipeline.
        /// </summary>
        public readonly bool? EnableLogging;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        /// </summary>
        public readonly string? LogGroupId;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        /// </summary>
        public readonly string? LogId;

        [OutputConstructor]
        private PipelineLogConfigurationDetails(
            bool? enableAutoLogCreation,

            bool? enableLogging,

            string? logGroupId,

            string? logId)
        {
            EnableAutoLogCreation = enableAutoLogCreation;
            EnableLogging = enableLogging;
            LogGroupId = logGroupId;
            LogId = logId;
        }
    }
}