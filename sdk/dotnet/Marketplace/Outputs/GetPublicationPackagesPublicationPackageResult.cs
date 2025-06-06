// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace.Outputs
{

    [OutputType]
    public sealed class GetPublicationPackagesPublicationPackageResult
    {
        /// <summary>
        /// The ID of the listing that the specified package belongs to.
        /// </summary>
        public readonly string ListingId;
        /// <summary>
        /// A filter to return only packages that match the given package type exactly.
        /// </summary>
        public readonly string PackageType;
        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        public readonly string PackageVersion;
        /// <summary>
        /// The unique identifier for the package resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// The date and time the publication package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetPublicationPackagesPublicationPackageResult(
            string listingId,

            string packageType,

            string packageVersion,

            string resourceId,

            string timeCreated)
        {
            ListingId = listingId;
            PackageType = packageType;
            PackageVersion = packageVersion;
            ResourceId = resourceId;
            TimeCreated = timeCreated;
        }
    }
}
