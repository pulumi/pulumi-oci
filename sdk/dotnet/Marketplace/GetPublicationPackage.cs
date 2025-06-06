// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace
{
    public static class GetPublicationPackage
    {
        /// <summary>
        /// This data source provides details about a specific Publication Package resource in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Gets the details of a specific package version within a given publication.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPublicationPackage = Oci.Marketplace.GetPublicationPackage.Invoke(new()
        ///     {
        ///         PackageVersion = publicationPackagePackageVersion,
        ///         PublicationId = testPublication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPublicationPackageResult> InvokeAsync(GetPublicationPackageArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPublicationPackageResult>("oci:Marketplace/getPublicationPackage:getPublicationPackage", args ?? new GetPublicationPackageArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Publication Package resource in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Gets the details of a specific package version within a given publication.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPublicationPackage = Oci.Marketplace.GetPublicationPackage.Invoke(new()
        ///     {
        ///         PackageVersion = publicationPackagePackageVersion,
        ///         PublicationId = testPublication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPublicationPackageResult> Invoke(GetPublicationPackageInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPublicationPackageResult>("oci:Marketplace/getPublicationPackage:getPublicationPackage", args ?? new GetPublicationPackageInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Publication Package resource in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Gets the details of a specific package version within a given publication.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPublicationPackage = Oci.Marketplace.GetPublicationPackage.Invoke(new()
        ///     {
        ///         PackageVersion = publicationPackagePackageVersion,
        ///         PublicationId = testPublication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPublicationPackageResult> Invoke(GetPublicationPackageInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPublicationPackageResult>("oci:Marketplace/getPublicationPackage:getPublicationPackage", args ?? new GetPublicationPackageInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPublicationPackageArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        [Input("packageVersion", required: true)]
        public string PackageVersion { get; set; } = null!;

        /// <summary>
        /// The unique identifier for the publication.
        /// </summary>
        [Input("publicationId", required: true)]
        public string PublicationId { get; set; } = null!;

        public GetPublicationPackageArgs()
        {
        }
        public static new GetPublicationPackageArgs Empty => new GetPublicationPackageArgs();
    }

    public sealed class GetPublicationPackageInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The version of the package. Package versions are unique within a listing.
        /// </summary>
        [Input("packageVersion", required: true)]
        public Input<string> PackageVersion { get; set; } = null!;

        /// <summary>
        /// The unique identifier for the publication.
        /// </summary>
        [Input("publicationId", required: true)]
        public Input<string> PublicationId { get; set; } = null!;

        public GetPublicationPackageInvokeArgs()
        {
        }
        public static new GetPublicationPackageInvokeArgs Empty => new GetPublicationPackageInvokeArgs();
    }


    [OutputType]
    public sealed class GetPublicationPackageResult
    {
        /// <summary>
        /// The ID of the listing resource associated with this publication package. For more information, see [AppCatalogListing](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/latest/AppCatalogListing/) in the Core Services API.
        /// </summary>
        public readonly string AppCatalogListingId;
        /// <summary>
        /// The resource version of the listing resource associated with this publication package.
        /// </summary>
        public readonly string AppCatalogListingResourceVersion;
        /// <summary>
        /// A description of the variable.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The ID of the image that corresponds to the package.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// The ID of the listing that the specified package belongs to.
        /// </summary>
        public readonly string ListingId;
        /// <summary>
        /// The operating system used by the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicationPackageOperatingSystemResult> OperatingSystems;
        /// <summary>
        /// The specified package's type.
        /// </summary>
        public readonly string PackageType;
        public readonly string PackageVersion;
        public readonly string PublicationId;
        /// <summary>
        /// The unique identifier for the package resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// A link to the stack resource.
        /// </summary>
        public readonly string ResourceLink;
        /// <summary>
        /// The date and time the publication package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// A list of variables for the stack resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicationPackageVariableResult> Variables;
        /// <summary>
        /// The package version.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetPublicationPackageResult(
            string appCatalogListingId,

            string appCatalogListingResourceVersion,

            string description,

            string id,

            string imageId,

            string listingId,

            ImmutableArray<Outputs.GetPublicationPackageOperatingSystemResult> operatingSystems,

            string packageType,

            string packageVersion,

            string publicationId,

            string resourceId,

            string resourceLink,

            string timeCreated,

            ImmutableArray<Outputs.GetPublicationPackageVariableResult> variables,

            string version)
        {
            AppCatalogListingId = appCatalogListingId;
            AppCatalogListingResourceVersion = appCatalogListingResourceVersion;
            Description = description;
            Id = id;
            ImageId = imageId;
            ListingId = listingId;
            OperatingSystems = operatingSystems;
            PackageType = packageType;
            PackageVersion = packageVersion;
            PublicationId = publicationId;
            ResourceId = resourceId;
            ResourceLink = resourceLink;
            TimeCreated = timeCreated;
            Variables = variables;
            Version = version;
        }
    }
}
