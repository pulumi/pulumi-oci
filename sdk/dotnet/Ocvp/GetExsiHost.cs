// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp
{
    public static class GetExsiHost
    {
        /// <summary>
        /// This data source provides details about a specific Esxi Host resource in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Gets the specified ESXi host's information.
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
        ///     var testEsxiHost = Oci.Ocvp.GetExsiHost.Invoke(new()
        ///     {
        ///         EsxiHostId = oci_ocvp_esxi_host.Test_esxi_host.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetExsiHostResult> InvokeAsync(GetExsiHostArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetExsiHostResult>("oci:Ocvp/getExsiHost:getExsiHost", args ?? new GetExsiHostArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Esxi Host resource in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Gets the specified ESXi host's information.
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
        ///     var testEsxiHost = Oci.Ocvp.GetExsiHost.Invoke(new()
        ///     {
        ///         EsxiHostId = oci_ocvp_esxi_host.Test_esxi_host.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetExsiHostResult> Invoke(GetExsiHostInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetExsiHostResult>("oci:Ocvp/getExsiHost:getExsiHost", args ?? new GetExsiHostInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExsiHostArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host.
        /// </summary>
        [Input("esxiHostId", required: true)]
        public string EsxiHostId { get; set; } = null!;

        public GetExsiHostArgs()
        {
        }
        public static new GetExsiHostArgs Empty => new GetExsiHostArgs();
    }

    public sealed class GetExsiHostInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host.
        /// </summary>
        [Input("esxiHostId", required: true)]
        public Input<string> EsxiHostId { get; set; } = null!;

        public GetExsiHostInvokeArgs()
        {
        }
        public static new GetExsiHostInvokeArgs Empty => new GetExsiHostInvokeArgs();
    }


    [OutputType]
    public sealed class GetExsiHostResult
    {
        /// <summary>
        /// Current billing cycle end date. If the value in `currentSku` and `nextSku` are different, the value specified in `nextSku` becomes the new `currentSKU` when the `contractEndDate` is reached. Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string BillingContractEndDate;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Capacity Reservation.
        /// </summary>
        public readonly string CapacityReservationId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the SDDC.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The availability domain of the ESXi host.
        /// </summary>
        public readonly string ComputeAvailabilityDomain;
        /// <summary>
        /// In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
        /// </summary>
        public readonly string ComputeInstanceId;
        /// <summary>
        /// The billing option currently used by the ESXi host. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
        /// </summary>
        public readonly string CurrentSku;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A descriptive name for the ESXi host. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        public readonly string EsxiHostId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the esxi host that is failed.
        /// </summary>
        public readonly string FailedEsxiHostId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The date and time when the new esxi host should start billing cycle. [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2021-07-25T21:10:29.600Z`
        /// </summary>
        public readonly string GracePeriodEndDate;
        /// <summary>
        /// The OCPU count of the ESXi host.
        /// </summary>
        public readonly double HostOcpuCount;
        /// <summary>
        /// The compute shape name of the ESXi host. [ListSupportedHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedHostShapes/ListSupportedHostShapes).
        /// </summary>
        public readonly string HostShapeName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ESXi host.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The billing option to switch to after the current billing cycle ends. If `nextSku` is null or empty, `currentSku` continues to the next billing cycle. [ListSupportedSkus](https://docs.cloud.oracle.com/iaas/api/#/en/vmware/20200501/SupportedSkuSummary/ListSupportedSkus).
        /// </summary>
        public readonly string NextSku;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the esxi host that is newly created to replace the failed node.
        /// </summary>
        public readonly string ReplacementEsxiHostId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
        /// </summary>
        public readonly string SddcId;
        /// <summary>
        /// The current state of the ESXi host.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the ESXi host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the ESXi host was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetExsiHostResult(
            string billingContractEndDate,

            string capacityReservationId,

            string compartmentId,

            string computeAvailabilityDomain,

            string computeInstanceId,

            string currentSku,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string esxiHostId,

            string failedEsxiHostId,

            ImmutableDictionary<string, object> freeformTags,

            string gracePeriodEndDate,

            double hostOcpuCount,

            string hostShapeName,

            string id,

            string nextSku,

            string replacementEsxiHostId,

            string sddcId,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            BillingContractEndDate = billingContractEndDate;
            CapacityReservationId = capacityReservationId;
            CompartmentId = compartmentId;
            ComputeAvailabilityDomain = computeAvailabilityDomain;
            ComputeInstanceId = computeInstanceId;
            CurrentSku = currentSku;
            DefinedTags = definedTags;
            DisplayName = displayName;
            EsxiHostId = esxiHostId;
            FailedEsxiHostId = failedEsxiHostId;
            FreeformTags = freeformTags;
            GracePeriodEndDate = gracePeriodEndDate;
            HostOcpuCount = hostOcpuCount;
            HostShapeName = hostShapeName;
            Id = id;
            NextSku = nextSku;
            ReplacementEsxiHostId = replacementEsxiHostId;
            SddcId = sddcId;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}