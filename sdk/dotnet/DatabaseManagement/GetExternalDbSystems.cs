// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalDbSystems
    {
        /// <summary>
        /// This data source provides the list of External Db Systems in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the external DB systems in the specified compartment.
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
        ///     var testExternalDbSystems = Oci.DatabaseManagement.GetExternalDbSystems.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalDbSystemDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalDbSystemsResult> InvokeAsync(GetExternalDbSystemsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalDbSystemsResult>("oci:DatabaseManagement/getExternalDbSystems:getExternalDbSystems", args ?? new GetExternalDbSystemsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of External Db Systems in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the external DB systems in the specified compartment.
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
        ///     var testExternalDbSystems = Oci.DatabaseManagement.GetExternalDbSystems.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalDbSystemDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalDbSystemsResult> Invoke(GetExternalDbSystemsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalDbSystemsResult>("oci:DatabaseManagement/getExternalDbSystems:getExternalDbSystems", args ?? new GetExternalDbSystemsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of External Db Systems in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the external DB systems in the specified compartment.
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
        ///     var testExternalDbSystems = Oci.DatabaseManagement.GetExternalDbSystems.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = externalDbSystemDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalDbSystemsResult> Invoke(GetExternalDbSystemsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalDbSystemsResult>("oci:DatabaseManagement/getExternalDbSystems:getExternalDbSystems", args ?? new GetExternalDbSystemsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalDbSystemsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetExternalDbSystemsFilterArgs>? _filters;
        public List<Inputs.GetExternalDbSystemsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetExternalDbSystemsFilterArgs>());
            set => _filters = value;
        }

        public GetExternalDbSystemsArgs()
        {
        }
        public static new GetExternalDbSystemsArgs Empty => new GetExternalDbSystemsArgs();
    }

    public sealed class GetExternalDbSystemsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to only return the resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetExternalDbSystemsFilterInputArgs>? _filters;
        public InputList<Inputs.GetExternalDbSystemsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetExternalDbSystemsFilterInputArgs>());
            set => _filters = value;
        }

        public GetExternalDbSystemsInvokeArgs()
        {
        }
        public static new GetExternalDbSystemsInvokeArgs Empty => new GetExternalDbSystemsInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalDbSystemsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-friendly name for the DB system. The name does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The list of external_db_system_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalDbSystemsExternalDbSystemCollectionResult> ExternalDbSystemCollections;
        public readonly ImmutableArray<Outputs.GetExternalDbSystemsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetExternalDbSystemsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetExternalDbSystemsExternalDbSystemCollectionResult> externalDbSystemCollections,

            ImmutableArray<Outputs.GetExternalDbSystemsFilterResult> filters,

            string id)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            ExternalDbSystemCollections = externalDbSystemCollections;
            Filters = filters;
            Id = id;
        }
    }
}
