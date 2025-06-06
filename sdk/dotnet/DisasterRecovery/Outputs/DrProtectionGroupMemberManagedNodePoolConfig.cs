// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Outputs
{

    [OutputType]
    public sealed class DrProtectionGroupMemberManagedNodePoolConfig
    {
        /// <summary>
        /// (Updatable) The OCID of the managed node pool in OKE cluster.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// (Updatable) The maximum number to which nodes in the managed node pool could be scaled up.
        /// </summary>
        public readonly int? Maximum;
        /// <summary>
        /// (Updatable) The minimum number to which nodes in the managed node pool could be scaled down.
        /// </summary>
        public readonly int? Minimum;

        [OutputConstructor]
        private DrProtectionGroupMemberManagedNodePoolConfig(
            string? id,

            int? maximum,

            int? minimum)
        {
            Id = id;
            Maximum = maximum;
            Minimum = minimum;
        }
    }
}
