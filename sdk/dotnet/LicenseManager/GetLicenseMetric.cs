// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LicenseManager
{
    public static class GetLicenseMetric
    {
        /// <summary>
        /// This data source provides details about a specific License Metric resource in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves the license metrics for a given compartment.
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
        ///     var testLicenseMetric = Oci.LicenseManager.GetLicenseMetric.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCompartmentIdInSubtree = @var.License_metric_is_compartment_id_in_subtree,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetLicenseMetricResult> InvokeAsync(GetLicenseMetricArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLicenseMetricResult>("oci:LicenseManager/getLicenseMetric:getLicenseMetric", args ?? new GetLicenseMetricArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific License Metric resource in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves the license metrics for a given compartment.
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
        ///     var testLicenseMetric = Oci.LicenseManager.GetLicenseMetric.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCompartmentIdInSubtree = @var.License_metric_is_compartment_id_in_subtree,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetLicenseMetricResult> Invoke(GetLicenseMetricInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetLicenseMetricResult>("oci:LicenseManager/getLicenseMetric:getLicenseMetric", args ?? new GetLicenseMetricInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetLicenseMetricArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Indicates if the given compartment is the root compartment.
        /// </summary>
        [Input("isCompartmentIdInSubtree")]
        public bool? IsCompartmentIdInSubtree { get; set; }

        public GetLicenseMetricArgs()
        {
        }
        public static new GetLicenseMetricArgs Empty => new GetLicenseMetricArgs();
    }

    public sealed class GetLicenseMetricInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Indicates if the given compartment is the root compartment.
        /// </summary>
        [Input("isCompartmentIdInSubtree")]
        public Input<bool>? IsCompartmentIdInSubtree { get; set; }

        public GetLicenseMetricInvokeArgs()
        {
        }
        public static new GetLicenseMetricInvokeArgs Empty => new GetLicenseMetricInvokeArgs();
    }


    [OutputType]
    public sealed class GetLicenseMetricResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsCompartmentIdInSubtree;
        /// <summary>
        /// Total number of license records that will expire within 90 days in a particular compartment.
        /// </summary>
        public readonly int LicenseRecordExpiringSoonCount;
        /// <summary>
        /// Total number of BYOL instances in a particular compartment.
        /// </summary>
        public readonly int TotalByolInstanceCount;
        /// <summary>
        /// Total number of License Included (LI) instances in a particular compartment.
        /// </summary>
        public readonly int TotalLicenseIncludedInstanceCount;
        /// <summary>
        /// Total number of product licenses in a particular compartment.
        /// </summary>
        public readonly int TotalProductLicenseCount;

        [OutputConstructor]
        private GetLicenseMetricResult(
            string compartmentId,

            string id,

            bool? isCompartmentIdInSubtree,

            int licenseRecordExpiringSoonCount,

            int totalByolInstanceCount,

            int totalLicenseIncludedInstanceCount,

            int totalProductLicenseCount)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsCompartmentIdInSubtree = isCompartmentIdInSubtree;
            LicenseRecordExpiringSoonCount = licenseRecordExpiringSoonCount;
            TotalByolInstanceCount = totalByolInstanceCount;
            TotalLicenseIncludedInstanceCount = totalLicenseIncludedInstanceCount;
            TotalProductLicenseCount = totalProductLicenseCount;
        }
    }
}