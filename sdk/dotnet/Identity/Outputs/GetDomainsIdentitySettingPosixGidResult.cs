// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsIdentitySettingPosixGidResult
    {
        /// <summary>
        /// The number at which the Posix Uid Manual assignment ends.
        /// </summary>
        public readonly int ManualAssignmentEndsAt;
        /// <summary>
        /// The number from which the Posix Uid Manual assignment starts.
        /// </summary>
        public readonly int ManualAssignmentStartsFrom;

        [OutputConstructor]
        private GetDomainsIdentitySettingPosixGidResult(
            int manualAssignmentEndsAt,

            int manualAssignmentStartsFrom)
        {
            ManualAssignmentEndsAt = manualAssignmentEndsAt;
            ManualAssignmentStartsFrom = manualAssignmentStartsFrom;
        }
    }
}
