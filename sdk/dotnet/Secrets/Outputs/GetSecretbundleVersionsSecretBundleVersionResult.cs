// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Secrets.Outputs
{

    [OutputType]
    public sealed class GetSecretbundleVersionsSecretBundleVersionResult
    {
        /// <summary>
        /// The OCID of the secret.
        /// </summary>
        public readonly string SecretId;
        /// <summary>
        /// A list of possible rotation states for the secret bundle.
        /// </summary>
        public readonly ImmutableArray<string> Stages;
        /// <summary>
        /// The time when the secret bundle was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeOfDeletion;
        /// <summary>
        /// An optional property indicating when the secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeOfExpiry;
        /// <summary>
        /// The version name of the secret bundle, as provided when the secret was created or last rotated.
        /// </summary>
        public readonly string VersionName;
        /// <summary>
        /// The version number of the secret.
        /// </summary>
        public readonly string VersionNumber;

        [OutputConstructor]
        private GetSecretbundleVersionsSecretBundleVersionResult(
            string secretId,

            ImmutableArray<string> stages,

            string timeCreated,

            string timeOfDeletion,

            string timeOfExpiry,

            string versionName,

            string versionNumber)
        {
            SecretId = secretId;
            Stages = stages;
            TimeCreated = timeCreated;
            TimeOfDeletion = timeOfDeletion;
            TimeOfExpiry = timeOfExpiry;
            VersionName = versionName;
            VersionNumber = versionNumber;
        }
    }
}
