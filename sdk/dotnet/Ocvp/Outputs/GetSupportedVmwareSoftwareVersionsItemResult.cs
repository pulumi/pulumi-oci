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
    public sealed class GetSupportedVmwareSoftwareVersionsItemResult
    {
        /// <summary>
        /// A description of the software in the bundle.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A list of supported ESXi software versions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsItemEsxiSoftwareVersionResult> EsxiSoftwareVersions;
        /// <summary>
        /// A filter to return only resources that match the given VMware software version exactly.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetSupportedVmwareSoftwareVersionsItemResult(
            string description,

            ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsItemEsxiSoftwareVersionResult> esxiSoftwareVersions,

            string version)
        {
            Description = description;
            EsxiSoftwareVersions = esxiSoftwareVersions;
            Version = version;
        }
    }
}
