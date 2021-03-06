// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetAvailabilityDomain
    {
        /// <summary>
        /// This data source provides the details of a single Availability Domain in Oracle Cloud Infrastructure Identity service.
        /// 
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
        ///         var testCompartment = Output.Create(Oci.Identity.GetAvailabilityDomain.InvokeAsync(new Oci.Identity.GetAvailabilityDomainArgs
        ///         {
        ///             CompartmentId = @var.Tenancy_ocid,
        ///             Id = @var.Id,
        ///             AdNumber = @var.Ad_number,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAvailabilityDomainResult> InvokeAsync(GetAvailabilityDomainArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAvailabilityDomainResult>("oci:Identity/getAvailabilityDomain:getAvailabilityDomain", args ?? new GetAvailabilityDomainArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the details of a single Availability Domain in Oracle Cloud Infrastructure Identity service.
        /// 
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
        ///         var testCompartment = Output.Create(Oci.Identity.GetAvailabilityDomain.InvokeAsync(new Oci.Identity.GetAvailabilityDomainArgs
        ///         {
        ///             CompartmentId = @var.Tenancy_ocid,
        ///             Id = @var.Id,
        ///             AdNumber = @var.Ad_number,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAvailabilityDomainResult> Invoke(GetAvailabilityDomainInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAvailabilityDomainResult>("oci:Identity/getAvailabilityDomain:getAvailabilityDomain", args ?? new GetAvailabilityDomainInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAvailabilityDomainArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The number of the Availability Domain. Required if `id` is not specified. This number corresponds to the integer in the Availability Domain `name`.
        /// </summary>
        [Input("adNumber")]
        public int? AdNumber { get; set; }

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The OCID of the Availability Domain. Required if `ad_number` is not specified.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        public GetAvailabilityDomainArgs()
        {
        }
    }

    public sealed class GetAvailabilityDomainInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The number of the Availability Domain. Required if `id` is not specified. This number corresponds to the integer in the Availability Domain `name`.
        /// </summary>
        [Input("adNumber")]
        public Input<int>? AdNumber { get; set; }

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The OCID of the Availability Domain. Required if `ad_number` is not specified.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public GetAvailabilityDomainInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAvailabilityDomainResult
    {
        /// <summary>
        /// The number of the Availability Domain. For example, the `ad_number` for YXol:US-ASHBURN-AD-1 would be "1"
        /// </summary>
        public readonly int AdNumber;
        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID of the Availability Domain.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the Availability Domain.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetAvailabilityDomainResult(
            int adNumber,

            string compartmentId,

            string id,

            string name)
        {
            AdNumber = adNumber;
            CompartmentId = compartmentId;
            Id = id;
            Name = name;
        }
    }
}
