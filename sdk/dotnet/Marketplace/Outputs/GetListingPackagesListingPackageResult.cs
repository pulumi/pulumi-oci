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
    public sealed class GetListingPackagesListingPackageResult
    {
        /// <summary>
        /// The unique identifier for the listing.
        /// </summary>
        public readonly string ListingId;
        /// <summary>
        /// The operating system used by the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingPackagesListingPackageOperatingSystemResult> OperatingSystems;
        /// <summary>
        /// A filter to return only packages that match the given package type exactly.
        /// </summary>
        public readonly string PackageType;
        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        public readonly string PackageVersion;
        /// <summary>
        /// The model for pricing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingPackagesListingPackagePricingResult> Pricings;
        /// <summary>
        /// The regions where you can deploy the listing package. (Some packages have restrictions that limit their deployment to United States regions only.)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingPackagesListingPackageRegionResult> Regions;
        /// <summary>
        /// The unique identifier for the package resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetListingPackagesListingPackageResult(
            string listingId,

            ImmutableArray<Outputs.GetListingPackagesListingPackageOperatingSystemResult> operatingSystems,

            string packageType,

            string packageVersion,

            ImmutableArray<Outputs.GetListingPackagesListingPackagePricingResult> pricings,

            ImmutableArray<Outputs.GetListingPackagesListingPackageRegionResult> regions,

            string resourceId,

            string timeCreated)
        {
            ListingId = listingId;
            OperatingSystems = operatingSystems;
            PackageType = packageType;
            PackageVersion = packageVersion;
            Pricings = pricings;
            Regions = regions;
            ResourceId = resourceId;
            TimeCreated = timeCreated;
        }
    }
}
