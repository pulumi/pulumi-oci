// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class GetSddcVsphereUpgradeObjectResult
    {
        /// <summary>
        /// Binary object download link.
        /// </summary>
        public readonly string DownloadLink;
        /// <summary>
        /// Binary object description.
        /// </summary>
        public readonly string LinkDescription;

        [OutputConstructor]
        private GetSddcVsphereUpgradeObjectResult(
            string downloadLink,

            string linkDescription)
        {
            DownloadLink = downloadLink;
            LinkDescription = linkDescription;
        }
    }
}
