// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceCatalog
{
    public static class GetPrivateApplications
    {
        /// <summary>
        /// This data source provides the list of Private Applications in Oracle Cloud Infrastructure Service Catalog service.
        /// 
        /// Lists all the private applications in a given compartment.
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
        ///     var testPrivateApplications = Oci.ServiceCatalog.GetPrivateApplications.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Private_application_display_name,
        ///         PrivateApplicationId = oci_service_catalog_private_application.Test_private_application.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPrivateApplicationsResult> InvokeAsync(GetPrivateApplicationsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPrivateApplicationsResult>("oci:ServiceCatalog/getPrivateApplications:getPrivateApplications", args ?? new GetPrivateApplicationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Private Applications in Oracle Cloud Infrastructure Service Catalog service.
        /// 
        /// Lists all the private applications in a given compartment.
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
        ///     var testPrivateApplications = Oci.ServiceCatalog.GetPrivateApplications.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Private_application_display_name,
        ///         PrivateApplicationId = oci_service_catalog_private_application.Test_private_application.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPrivateApplicationsResult> Invoke(GetPrivateApplicationsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetPrivateApplicationsResult>("oci:ServiceCatalog/getPrivateApplications:getPrivateApplications", args ?? new GetPrivateApplicationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPrivateApplicationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Exact match name filter.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetPrivateApplicationsFilterArgs>? _filters;
        public List<Inputs.GetPrivateApplicationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPrivateApplicationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier for the private application.
        /// </summary>
        [Input("privateApplicationId")]
        public string? PrivateApplicationId { get; set; }

        public GetPrivateApplicationsArgs()
        {
        }
        public static new GetPrivateApplicationsArgs Empty => new GetPrivateApplicationsArgs();
    }

    public sealed class GetPrivateApplicationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Exact match name filter.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetPrivateApplicationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPrivateApplicationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPrivateApplicationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier for the private application.
        /// </summary>
        [Input("privateApplicationId")]
        public Input<string>? PrivateApplicationId { get; set; }

        public GetPrivateApplicationsInvokeArgs()
        {
        }
        public static new GetPrivateApplicationsInvokeArgs Empty => new GetPrivateApplicationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetPrivateApplicationsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name used to refer to the uploaded data.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetPrivateApplicationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of private_application_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPrivateApplicationsPrivateApplicationCollectionResult> PrivateApplicationCollections;
        public readonly string? PrivateApplicationId;

        [OutputConstructor]
        private GetPrivateApplicationsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetPrivateApplicationsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetPrivateApplicationsPrivateApplicationCollectionResult> privateApplicationCollections,

            string? privateApplicationId)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            PrivateApplicationCollections = privateApplicationCollections;
            PrivateApplicationId = privateApplicationId;
        }
    }
}