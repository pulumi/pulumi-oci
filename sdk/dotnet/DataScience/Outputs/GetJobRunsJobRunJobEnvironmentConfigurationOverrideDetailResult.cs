// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetJobRunsJobRunJobEnvironmentConfigurationOverrideDetailResult
    {
        /// <summary>
        /// The container image run [CMD](https://docs.docker.com/engine/reference/builder/#cmd) as a list of strings. Use `CMD` as arguments to the `ENTRYPOINT` or the only command to run in the absence of an `ENTRYPOINT`. The combined size of `CMD` and `ENTRYPOINT` must be less than 2048 bytes.
        /// </summary>
        public readonly ImmutableArray<string> Cmds;
        /// <summary>
        /// The container image run [ENTRYPOINT](https://docs.docker.com/engine/reference/builder/#entrypoint) as a list of strings. Accept the `CMD` as extra arguments. The combined size of `CMD` and `ENTRYPOINT` must be less than 2048 bytes. More information on how `CMD` and `ENTRYPOINT` interact are [here](https://docs.docker.com/engine/reference/builder/#understand-how-cmd-and-entrypoint-interact).
        /// </summary>
        public readonly ImmutableArray<string> Entrypoints;
        /// <summary>
        /// The full path to the Oracle Container Repository (OCIR) registry, image, and tag in a canonical format. Acceptable format: `&lt;region&gt;.ocir.io/&lt;registry&gt;/&lt;image&gt;:&lt;tag&gt;` `&lt;region&gt;.ocir.io/&lt;registry&gt;/&lt;image&gt;:&lt;tag&gt;@digest`
        /// </summary>
        public readonly string Image;
        /// <summary>
        /// The digest of the container image. For example, `sha256:881303a6b2738834d795a32b4a98eb0e5e3d1cad590a712d1e04f9b2fa90a030`
        /// </summary>
        public readonly string ImageDigest;
        /// <summary>
        /// OCID of the container image signature
        /// </summary>
        public readonly string ImageSignatureId;
        /// <summary>
        /// The environment configuration type used for job runtime.
        /// </summary>
        public readonly string JobEnvironmentType;

        [OutputConstructor]
        private GetJobRunsJobRunJobEnvironmentConfigurationOverrideDetailResult(
            ImmutableArray<string> cmds,

            ImmutableArray<string> entrypoints,

            string image,

            string imageDigest,

            string imageSignatureId,

            string jobEnvironmentType)
        {
            Cmds = cmds;
            Entrypoints = entrypoints;
            Image = image;
            ImageDigest = imageDigest;
            ImageSignatureId = imageSignatureId;
            JobEnvironmentType = jobEnvironmentType;
        }
    }
}
