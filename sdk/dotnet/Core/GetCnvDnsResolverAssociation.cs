// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetCnvDnsResolverAssociation
    {
        /// <summary>
        /// This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Get the associated DNS resolver information with a vcn
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
        ///     var testVcnDnsResolverAssociation = Oci.Core.GetCnvDnsResolverAssociation.Invoke(new()
        ///     {
        ///         VcnId = testVcn.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetCnvDnsResolverAssociationResult> InvokeAsync(GetCnvDnsResolverAssociationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetCnvDnsResolverAssociationResult>("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", args ?? new GetCnvDnsResolverAssociationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Get the associated DNS resolver information with a vcn
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
        ///     var testVcnDnsResolverAssociation = Oci.Core.GetCnvDnsResolverAssociation.Invoke(new()
        ///     {
        ///         VcnId = testVcn.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCnvDnsResolverAssociationResult> Invoke(GetCnvDnsResolverAssociationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetCnvDnsResolverAssociationResult>("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", args ?? new GetCnvDnsResolverAssociationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Get the associated DNS resolver information with a vcn
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
        ///     var testVcnDnsResolverAssociation = Oci.Core.GetCnvDnsResolverAssociation.Invoke(new()
        ///     {
        ///         VcnId = testVcn.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCnvDnsResolverAssociationResult> Invoke(GetCnvDnsResolverAssociationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetCnvDnsResolverAssociationResult>("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", args ?? new GetCnvDnsResolverAssociationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetCnvDnsResolverAssociationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId", required: true)]
        public string VcnId { get; set; } = null!;

        public GetCnvDnsResolverAssociationArgs()
        {
        }
        public static new GetCnvDnsResolverAssociationArgs Empty => new GetCnvDnsResolverAssociationArgs();
    }

    public sealed class GetCnvDnsResolverAssociationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId", required: true)]
        public Input<string> VcnId { get; set; } = null!;

        public GetCnvDnsResolverAssociationInvokeArgs()
        {
        }
        public static new GetCnvDnsResolverAssociationInvokeArgs Empty => new GetCnvDnsResolverAssociationInvokeArgs();
    }


    [OutputType]
    public sealed class GetCnvDnsResolverAssociationResult
    {
        /// <summary>
        /// The OCID of the DNS resolver in the association. We won't have the DNS resolver id as soon as vcn 
        /// is created, we will create it asynchronously. It would be null until it is actually created.
        /// </summary>
        public readonly string DnsResolverId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string State;
        /// <summary>
        /// The OCID of the VCN in the association.
        /// </summary>
        public readonly string VcnId;

        [OutputConstructor]
        private GetCnvDnsResolverAssociationResult(
            string dnsResolverId,

            string id,

            string state,

            string vcnId)
        {
            DnsResolverId = dnsResolverId;
            Id = id;
            State = state;
            VcnId = vcnId;
        }
    }
}
