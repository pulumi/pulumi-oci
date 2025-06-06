// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LicenseManager
{
    public static class GetLicenseRecords
    {
        /// <summary>
        /// This data source provides the list of License Records in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves all license records for a given product license ID.
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
        ///     var testLicenseRecords = Oci.LicenseManager.GetLicenseRecords.Invoke(new()
        ///     {
        ///         ProductLicenseId = testProductLicense.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetLicenseRecordsResult> InvokeAsync(GetLicenseRecordsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetLicenseRecordsResult>("oci:LicenseManager/getLicenseRecords:getLicenseRecords", args ?? new GetLicenseRecordsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of License Records in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves all license records for a given product license ID.
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
        ///     var testLicenseRecords = Oci.LicenseManager.GetLicenseRecords.Invoke(new()
        ///     {
        ///         ProductLicenseId = testProductLicense.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetLicenseRecordsResult> Invoke(GetLicenseRecordsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetLicenseRecordsResult>("oci:LicenseManager/getLicenseRecords:getLicenseRecords", args ?? new GetLicenseRecordsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of License Records in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves all license records for a given product license ID.
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
        ///     var testLicenseRecords = Oci.LicenseManager.GetLicenseRecords.Invoke(new()
        ///     {
        ///         ProductLicenseId = testProductLicense.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetLicenseRecordsResult> Invoke(GetLicenseRecordsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetLicenseRecordsResult>("oci:LicenseManager/getLicenseRecords:getLicenseRecords", args ?? new GetLicenseRecordsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetLicenseRecordsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetLicenseRecordsFilterArgs>? _filters;
        public List<Inputs.GetLicenseRecordsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLicenseRecordsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique product license identifier.
        /// </summary>
        [Input("productLicenseId", required: true)]
        public string ProductLicenseId { get; set; } = null!;

        public GetLicenseRecordsArgs()
        {
        }
        public static new GetLicenseRecordsArgs Empty => new GetLicenseRecordsArgs();
    }

    public sealed class GetLicenseRecordsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetLicenseRecordsFilterInputArgs>? _filters;
        public InputList<Inputs.GetLicenseRecordsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetLicenseRecordsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique product license identifier.
        /// </summary>
        [Input("productLicenseId", required: true)]
        public Input<string> ProductLicenseId { get; set; } = null!;

        public GetLicenseRecordsInvokeArgs()
        {
        }
        public static new GetLicenseRecordsInvokeArgs Empty => new GetLicenseRecordsInvokeArgs();
    }


    [OutputType]
    public sealed class GetLicenseRecordsResult
    {
        public readonly ImmutableArray<Outputs.GetLicenseRecordsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of license_record_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLicenseRecordsLicenseRecordCollectionResult> LicenseRecordCollections;
        /// <summary>
        /// The product license [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) with which the license record is associated.
        /// </summary>
        public readonly string ProductLicenseId;

        [OutputConstructor]
        private GetLicenseRecordsResult(
            ImmutableArray<Outputs.GetLicenseRecordsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetLicenseRecordsLicenseRecordCollectionResult> licenseRecordCollections,

            string productLicenseId)
        {
            Filters = filters;
            Id = id;
            LicenseRecordCollections = licenseRecordCollections;
            ProductLicenseId = productLicenseId;
        }
    }
}
