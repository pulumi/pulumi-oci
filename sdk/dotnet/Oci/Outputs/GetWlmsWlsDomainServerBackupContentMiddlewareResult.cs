// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetWlmsWlsDomainServerBackupContentMiddlewareResult
    {
        /// <summary>
        /// The list of patches installed in the middleware included in the backup.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWlmsWlsDomainServerBackupContentMiddlewarePatchResult> Patches;
        /// <summary>
        /// The version of the middleware binaries included in the backup.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetWlmsWlsDomainServerBackupContentMiddlewareResult(
            ImmutableArray<Outputs.GetWlmsWlsDomainServerBackupContentMiddlewarePatchResult> patches,

            string version)
        {
            Patches = patches;
            Version = version;
        }
    }
}
