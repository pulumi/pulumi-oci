// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetFastConnectProviderService
    {
        /// <summary>
        /// This data source provides details about a specific Fast Connect Provider Service resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified provider service.
        /// For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        /// 
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
        ///     var testFastConnectProviderService = Oci.Core.GetFastConnectProviderService.Invoke(new()
        ///     {
        ///         ProviderServiceId = testFastConnectProviderServices.FastConnectProviderServices[0].Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFastConnectProviderServiceResult> InvokeAsync(GetFastConnectProviderServiceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFastConnectProviderServiceResult>("oci:Core/getFastConnectProviderService:getFastConnectProviderService", args ?? new GetFastConnectProviderServiceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fast Connect Provider Service resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified provider service.
        /// For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        /// 
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
        ///     var testFastConnectProviderService = Oci.Core.GetFastConnectProviderService.Invoke(new()
        ///     {
        ///         ProviderServiceId = testFastConnectProviderServices.FastConnectProviderServices[0].Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFastConnectProviderServiceResult> Invoke(GetFastConnectProviderServiceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFastConnectProviderServiceResult>("oci:Core/getFastConnectProviderService:getFastConnectProviderService", args ?? new GetFastConnectProviderServiceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fast Connect Provider Service resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified provider service.
        /// For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        /// 
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
        ///     var testFastConnectProviderService = Oci.Core.GetFastConnectProviderService.Invoke(new()
        ///     {
        ///         ProviderServiceId = testFastConnectProviderServices.FastConnectProviderServices[0].Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFastConnectProviderServiceResult> Invoke(GetFastConnectProviderServiceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFastConnectProviderServiceResult>("oci:Core/getFastConnectProviderService:getFastConnectProviderService", args ?? new GetFastConnectProviderServiceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFastConnectProviderServiceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the provider service.
        /// </summary>
        [Input("providerServiceId", required: true)]
        public string ProviderServiceId { get; set; } = null!;

        public GetFastConnectProviderServiceArgs()
        {
        }
        public static new GetFastConnectProviderServiceArgs Empty => new GetFastConnectProviderServiceArgs();
    }

    public sealed class GetFastConnectProviderServiceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the provider service.
        /// </summary>
        [Input("providerServiceId", required: true)]
        public Input<string> ProviderServiceId { get; set; } = null!;

        public GetFastConnectProviderServiceInvokeArgs()
        {
        }
        public static new GetFastConnectProviderServiceInvokeArgs Empty => new GetFastConnectProviderServiceInvokeArgs();
    }


    [OutputType]
    public sealed class GetFastConnectProviderServiceResult
    {
        /// <summary>
        /// Who is responsible for managing the virtual circuit bandwidth.
        /// </summary>
        public readonly string BandwithShapeManagement;
        /// <summary>
        /// Who is responsible for managing the ASN information for the network at the other end of the connection from Oracle.
        /// </summary>
        public readonly string CustomerAsnManagement;
        /// <summary>
        /// The location of the provider's website or portal. This portal is where you can get information about the provider service, create a virtual circuit connection from the provider to Oracle Cloud Infrastructure, and retrieve your provider service key for that virtual circuit connection.  Example: `https://example.com`
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Who is responsible for managing the private peering BGP information.
        /// </summary>
        public readonly string PrivatePeeringBgpManagement;
        /// <summary>
        /// The name of the provider.
        /// </summary>
        public readonly string ProviderName;
        public readonly string ProviderServiceId;
        /// <summary>
        /// Who is responsible for managing the provider service key.
        /// </summary>
        public readonly string ProviderServiceKeyManagement;
        /// <summary>
        /// The name of the service offered by the provider.
        /// </summary>
        public readonly string ProviderServiceName;
        /// <summary>
        /// Who is responsible for managing the public peering BGP information.
        /// </summary>
        public readonly string PublicPeeringBgpManagement;
        /// <summary>
        /// Total number of cross-connect or cross-connect groups required for the virtual circuit.
        /// </summary>
        public readonly int RequiredTotalCrossConnects;
        /// <summary>
        /// An array of virtual circuit types supported by this service.
        /// </summary>
        public readonly ImmutableArray<string> SupportedVirtualCircuitTypes;
        /// <summary>
        /// Provider service type.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetFastConnectProviderServiceResult(
            string bandwithShapeManagement,

            string customerAsnManagement,

            string description,

            string id,

            string privatePeeringBgpManagement,

            string providerName,

            string providerServiceId,

            string providerServiceKeyManagement,

            string providerServiceName,

            string publicPeeringBgpManagement,

            int requiredTotalCrossConnects,

            ImmutableArray<string> supportedVirtualCircuitTypes,

            string type)
        {
            BandwithShapeManagement = bandwithShapeManagement;
            CustomerAsnManagement = customerAsnManagement;
            Description = description;
            Id = id;
            PrivatePeeringBgpManagement = privatePeeringBgpManagement;
            ProviderName = providerName;
            ProviderServiceId = providerServiceId;
            ProviderServiceKeyManagement = providerServiceKeyManagement;
            ProviderServiceName = providerServiceName;
            PublicPeeringBgpManagement = publicPeeringBgpManagement;
            RequiredTotalCrossConnects = requiredTotalCrossConnects;
            SupportedVirtualCircuitTypes = supportedVirtualCircuitTypes;
            Type = type;
        }
    }
}
