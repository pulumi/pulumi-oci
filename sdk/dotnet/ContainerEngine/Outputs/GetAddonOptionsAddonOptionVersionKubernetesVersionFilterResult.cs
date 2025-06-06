// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetAddonOptionsAddonOptionVersionKubernetesVersionFilterResult
    {
        /// <summary>
        /// The exact version of kubernetes that are compatible.
        /// </summary>
        public readonly ImmutableArray<string> ExactKubernetesVersions;
        /// <summary>
        /// The latest kubernetes version.
        /// </summary>
        public readonly string MaximumVersion;
        /// <summary>
        /// The earliest kubernetes version.
        /// </summary>
        public readonly string MinimalVersion;

        [OutputConstructor]
        private GetAddonOptionsAddonOptionVersionKubernetesVersionFilterResult(
            ImmutableArray<string> exactKubernetesVersions,

            string maximumVersion,

            string minimalVersion)
        {
            ExactKubernetesVersions = exactKubernetesVersions;
            MaximumVersion = maximumVersion;
            MinimalVersion = minimalVersion;
        }
    }
}
