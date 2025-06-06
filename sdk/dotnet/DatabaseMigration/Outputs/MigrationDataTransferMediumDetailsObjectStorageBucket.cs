// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class MigrationDataTransferMediumDetailsObjectStorageBucket
    {
        /// <summary>
        /// (Updatable) Bucket name.
        /// </summary>
        public readonly string? Bucket;
        /// <summary>
        /// (Updatable) Namespace name of the object store bucket.
        /// </summary>
        public readonly string? Namespace;

        [OutputConstructor]
        private MigrationDataTransferMediumDetailsObjectStorageBucket(
            string? bucket,

            string? @namespace)
        {
            Bucket = bucket;
            Namespace = @namespace;
        }
    }
}
