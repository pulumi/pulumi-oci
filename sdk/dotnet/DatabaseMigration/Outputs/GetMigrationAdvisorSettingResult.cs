// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationAdvisorSettingResult
    {
        /// <summary>
        /// True to not interrupt migration execution due to Pre-Migration Advisor errors. Default is false.
        /// </summary>
        public readonly bool IsIgnoreErrors;
        /// <summary>
        /// True to skip the Pre-Migration Advisor execution. Default is false.
        /// </summary>
        public readonly bool IsSkipAdvisor;

        [OutputConstructor]
        private GetMigrationAdvisorSettingResult(
            bool isIgnoreErrors,

            bool isSkipAdvisor)
        {
            IsIgnoreErrors = isIgnoreErrors;
            IsSkipAdvisor = isSkipAdvisor;
        }
    }
}