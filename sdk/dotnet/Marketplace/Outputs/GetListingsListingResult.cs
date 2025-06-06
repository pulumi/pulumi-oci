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
    public sealed class GetListingsListingResult
    {
        /// <summary>
        /// The model for upload data for images and icons.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingBannerResult> Banners;
        /// <summary>
        /// Product categories that the listing belongs to.
        /// </summary>
        public readonly ImmutableArray<string> Categories;
        /// <summary>
        /// The list of compatible architectures supported by the listing
        /// </summary>
        public readonly ImmutableArray<string> CompatibleArchitectures;
        /// <summary>
        /// The default package version.
        /// </summary>
        public readonly string DefaultPackageVersion;
        /// <summary>
        /// Links to additional documentation provided by the publisher specifically for the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingDocumentationLinkResult> DocumentationLinks;
        /// <summary>
        /// The model for upload data for images and icons.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingIconResult> Icons;
        /// <summary>
        /// The unique identifier for the publisher.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether to show only featured listings. If this is set to `false` or is omitted, then all listings will be returned.
        /// </summary>
        public readonly bool IsFeatured;
        /// <summary>
        /// The publisher category to which the listing belongs. The publisher category informs where the listing appears for use.
        /// </summary>
        public readonly string ListingType;
        /// <summary>
        /// The name of the listing.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// A filter to return only packages that match the given package type exactly.
        /// </summary>
        public readonly string PackageType;
        public readonly ImmutableArray<string> PricingTypes;
        /// <summary>
        /// Summary details about the publisher of the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingPublisherResult> Publishers;
        /// <summary>
        /// The regions where the listing is eligible to be deployed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingRegionResult> Regions;
        /// <summary>
        /// A short description of the listing.
        /// </summary>
        public readonly string ShortDescription;
        /// <summary>
        /// The list of operating systems supported by the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingSupportedOperatingSystemResult> SupportedOperatingSystems;

        [OutputConstructor]
        private GetListingsListingResult(
            ImmutableArray<Outputs.GetListingsListingBannerResult> banners,

            ImmutableArray<string> categories,

            ImmutableArray<string> compatibleArchitectures,

            string defaultPackageVersion,

            ImmutableArray<Outputs.GetListingsListingDocumentationLinkResult> documentationLinks,

            ImmutableArray<Outputs.GetListingsListingIconResult> icons,

            string id,

            bool isFeatured,

            string listingType,

            string name,

            string packageType,

            ImmutableArray<string> pricingTypes,

            ImmutableArray<Outputs.GetListingsListingPublisherResult> publishers,

            ImmutableArray<Outputs.GetListingsListingRegionResult> regions,

            string shortDescription,

            ImmutableArray<Outputs.GetListingsListingSupportedOperatingSystemResult> supportedOperatingSystems)
        {
            Banners = banners;
            Categories = categories;
            CompatibleArchitectures = compatibleArchitectures;
            DefaultPackageVersion = defaultPackageVersion;
            DocumentationLinks = documentationLinks;
            Icons = icons;
            Id = id;
            IsFeatured = isFeatured;
            ListingType = listingType;
            Name = name;
            PackageType = packageType;
            PricingTypes = pricingTypes;
            Publishers = publishers;
            Regions = regions;
            ShortDescription = shortDescription;
            SupportedOperatingSystems = supportedOperatingSystems;
        }
    }
}
