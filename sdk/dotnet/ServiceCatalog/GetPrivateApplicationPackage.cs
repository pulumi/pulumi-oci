// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceCatalog
{
    public static class GetPrivateApplicationPackage
    {
        /// <summary>
        /// This data source provides details about a specific Private Application Package resource in Oracle Cloud Infrastructure Service Catalog service.
        /// 
        /// Gets the details of a specific package within a given private application.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPrivateApplicationPackage = Oci.ServiceCatalog.GetPrivateApplicationPackage.Invoke(new()
        ///     {
        ///         PrivateApplicationPackageId = oci_service_catalog_private_application_package.Test_private_application_package.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPrivateApplicationPackageResult> InvokeAsync(GetPrivateApplicationPackageArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPrivateApplicationPackageResult>("oci:ServiceCatalog/getPrivateApplicationPackage:getPrivateApplicationPackage", args ?? new GetPrivateApplicationPackageArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Application Package resource in Oracle Cloud Infrastructure Service Catalog service.
        /// 
        /// Gets the details of a specific package within a given private application.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPrivateApplicationPackage = Oci.ServiceCatalog.GetPrivateApplicationPackage.Invoke(new()
        ///     {
        ///         PrivateApplicationPackageId = oci_service_catalog_private_application_package.Test_private_application_package.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPrivateApplicationPackageResult> Invoke(GetPrivateApplicationPackageInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetPrivateApplicationPackageResult>("oci:ServiceCatalog/getPrivateApplicationPackage:getPrivateApplicationPackage", args ?? new GetPrivateApplicationPackageInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPrivateApplicationPackageArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the private application package.
        /// </summary>
        [Input("privateApplicationPackageId", required: true)]
        public string PrivateApplicationPackageId { get; set; } = null!;

        public GetPrivateApplicationPackageArgs()
        {
        }
        public static new GetPrivateApplicationPackageArgs Empty => new GetPrivateApplicationPackageArgs();
    }

    public sealed class GetPrivateApplicationPackageInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the private application package.
        /// </summary>
        [Input("privateApplicationPackageId", required: true)]
        public Input<string> PrivateApplicationPackageId { get; set; } = null!;

        public GetPrivateApplicationPackageInvokeArgs()
        {
        }
        public static new GetPrivateApplicationPackageInvokeArgs Empty => new GetPrivateApplicationPackageInvokeArgs();
    }


    [OutputType]
    public sealed class GetPrivateApplicationPackageResult
    {
        public readonly string ContentUrl;
        /// <summary>
        /// The display name of the package.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string MimeType;
        /// <summary>
        /// The specified package's type.
        /// </summary>
        public readonly string PackageType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private application where the package is hosted.
        /// </summary>
        public readonly string PrivateApplicationId;
        public readonly string PrivateApplicationPackageId;
        /// <summary>
        /// The date and time the private application package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-27T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The package version.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetPrivateApplicationPackageResult(
            string contentUrl,

            string displayName,

            string id,

            string mimeType,

            string packageType,

            string privateApplicationId,

            string privateApplicationPackageId,

            string timeCreated,

            string version)
        {
            ContentUrl = contentUrl;
            DisplayName = displayName;
            Id = id;
            MimeType = mimeType;
            PackageType = packageType;
            PrivateApplicationId = privateApplicationId;
            PrivateApplicationPackageId = privateApplicationPackageId;
            TimeCreated = timeCreated;
            Version = version;
        }
    }
}