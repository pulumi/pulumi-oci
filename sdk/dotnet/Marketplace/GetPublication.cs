// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace
{
    public static class GetPublication
    {
        /// <summary>
        /// This data source provides details about a specific Publication resource in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Gets the details of the specified publication.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testPublication = Output.Create(Oci.Marketplace.GetPublication.InvokeAsync(new Oci.Marketplace.GetPublicationArgs
        ///         {
        ///             PublicationId = oci_marketplace_publication.Test_publication.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPublicationResult> InvokeAsync(GetPublicationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPublicationResult>("oci:Marketplace/getPublication:getPublication", args ?? new GetPublicationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Publication resource in Oracle Cloud Infrastructure Marketplace service.
        /// 
        /// Gets the details of the specified publication.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testPublication = Output.Create(Oci.Marketplace.GetPublication.InvokeAsync(new Oci.Marketplace.GetPublicationArgs
        ///         {
        ///             PublicationId = oci_marketplace_publication.Test_publication.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPublicationResult> Invoke(GetPublicationInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetPublicationResult>("oci:Marketplace/getPublication:getPublication", args ?? new GetPublicationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPublicationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the publication.
        /// </summary>
        [Input("publicationId", required: true)]
        public string PublicationId { get; set; } = null!;

        public GetPublicationArgs()
        {
        }
    }

    public sealed class GetPublicationInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the publication.
        /// </summary>
        [Input("publicationId", required: true)]
        public Input<string> PublicationId { get; set; } = null!;

        public GetPublicationInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPublicationResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the publication exists.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The model for upload data for images and icons.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicationIconResult> Icons;
        /// <summary>
        /// The unique identifier for the publication in Marketplace.
        /// </summary>
        public readonly string Id;
        public readonly bool IsAgreementAcknowledged;
        /// <summary>
        /// The publisher category to which the publication belongs. The publisher category informs where the listing appears for use.
        /// </summary>
        public readonly string ListingType;
        /// <summary>
        /// A long description of the publication to use in the listing.
        /// </summary>
        public readonly string LongDescription;
        /// <summary>
        /// The name of the operating system.
        /// </summary>
        public readonly string Name;
        public readonly ImmutableArray<Outputs.GetPublicationPackageDetailResult> PackageDetails;
        /// <summary>
        /// The listing's package type.
        /// </summary>
        public readonly string PackageType;
        public readonly string PublicationId;
        /// <summary>
        /// A short description of the publication to use in the listing.
        /// </summary>
        public readonly string ShortDescription;
        /// <summary>
        /// The lifecycle state of the publication.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Contact information for getting support from the publisher for the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicationSupportContactResult> SupportContacts;
        /// <summary>
        /// The list of operating systems supported by the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicationSupportedOperatingSystemResult> SupportedOperatingSystems;
        /// <summary>
        /// The date and time the publication was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetPublicationResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            ImmutableDictionary<string, object> freeformTags,

            ImmutableArray<Outputs.GetPublicationIconResult> icons,

            string id,

            bool isAgreementAcknowledged,

            string listingType,

            string longDescription,

            string name,

            ImmutableArray<Outputs.GetPublicationPackageDetailResult> packageDetails,

            string packageType,

            string publicationId,

            string shortDescription,

            string state,

            ImmutableArray<Outputs.GetPublicationSupportContactResult> supportContacts,

            ImmutableArray<Outputs.GetPublicationSupportedOperatingSystemResult> supportedOperatingSystems,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Icons = icons;
            Id = id;
            IsAgreementAcknowledged = isAgreementAcknowledged;
            ListingType = listingType;
            LongDescription = longDescription;
            Name = name;
            PackageDetails = packageDetails;
            PackageType = packageType;
            PublicationId = publicationId;
            ShortDescription = shortDescription;
            State = state;
            SupportContacts = supportContacts;
            SupportedOperatingSystems = supportedOperatingSystems;
            TimeCreated = timeCreated;
        }
    }
}
