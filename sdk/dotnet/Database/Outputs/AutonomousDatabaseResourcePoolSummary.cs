// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class AutonomousDatabaseResourcePoolSummary
    {
        /// <summary>
        /// Indicates if the long-term backup schedule should be deleted. The default value is `FALSE`.
        /// </summary>
        public readonly bool? IsDisabled;
        public readonly int? PoolSize;

        [OutputConstructor]
        private AutonomousDatabaseResourcePoolSummary(
            bool? isDisabled,

            int? poolSize)
        {
            IsDisabled = isDisabled;
            PoolSize = poolSize;
        }
    }
}