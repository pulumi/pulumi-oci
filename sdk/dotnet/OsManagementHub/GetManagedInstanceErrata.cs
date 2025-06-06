// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetManagedInstanceErrata
    {
        /// <summary>
        /// This data source provides the list of Managed Instance Errata in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a list of applicable errata on the managed instance.
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
        ///     var testManagedInstanceErrata = Oci.OsManagementHub.GetManagedInstanceErrata.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ClassificationTypes = managedInstanceErrataClassificationType,
        ///         CompartmentId = compartmentId,
        ///         Names = managedInstanceErrataName,
        ///         NameContains = managedInstanceErrataNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedInstanceErrataResult> InvokeAsync(GetManagedInstanceErrataArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedInstanceErrataResult>("oci:OsManagementHub/getManagedInstanceErrata:getManagedInstanceErrata", args ?? new GetManagedInstanceErrataArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Errata in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a list of applicable errata on the managed instance.
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
        ///     var testManagedInstanceErrata = Oci.OsManagementHub.GetManagedInstanceErrata.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ClassificationTypes = managedInstanceErrataClassificationType,
        ///         CompartmentId = compartmentId,
        ///         Names = managedInstanceErrataName,
        ///         NameContains = managedInstanceErrataNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedInstanceErrataResult> Invoke(GetManagedInstanceErrataInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedInstanceErrataResult>("oci:OsManagementHub/getManagedInstanceErrata:getManagedInstanceErrata", args ?? new GetManagedInstanceErrataInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Errata in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a list of applicable errata on the managed instance.
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
        ///     var testManagedInstanceErrata = Oci.OsManagementHub.GetManagedInstanceErrata.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ClassificationTypes = managedInstanceErrataClassificationType,
        ///         CompartmentId = compartmentId,
        ///         Names = managedInstanceErrataName,
        ///         NameContains = managedInstanceErrataNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedInstanceErrataResult> Invoke(GetManagedInstanceErrataInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedInstanceErrataResult>("oci:OsManagementHub/getManagedInstanceErrata:getManagedInstanceErrata", args ?? new GetManagedInstanceErrataInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedInstanceErrataArgs : global::Pulumi.InvokeArgs
    {
        [Input("classificationTypes")]
        private List<string>? _classificationTypes;

        /// <summary>
        /// A filter to return only packages that match the given update classification type.
        /// </summary>
        public List<string> ClassificationTypes
        {
            get => _classificationTypes ?? (_classificationTypes = new List<string>());
            set => _classificationTypes = value;
        }

        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetManagedInstanceErrataFilterArgs>? _filters;
        public List<Inputs.GetManagedInstanceErrataFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedInstanceErrataFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public string ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// A filter to return resources that may partially match the erratum name given.
        /// </summary>
        [Input("nameContains")]
        public string? NameContains { get; set; }

        [Input("names")]
        private List<string>? _names;

        /// <summary>
        /// The assigned erratum name. It's unique and not changeable.  Example: `ELSA-2020-5804`
        /// </summary>
        public List<string> Names
        {
            get => _names ?? (_names = new List<string>());
            set => _names = value;
        }

        public GetManagedInstanceErrataArgs()
        {
        }
        public static new GetManagedInstanceErrataArgs Empty => new GetManagedInstanceErrataArgs();
    }

    public sealed class GetManagedInstanceErrataInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("classificationTypes")]
        private InputList<string>? _classificationTypes;

        /// <summary>
        /// A filter to return only packages that match the given update classification type.
        /// </summary>
        public InputList<string> ClassificationTypes
        {
            get => _classificationTypes ?? (_classificationTypes = new InputList<string>());
            set => _classificationTypes = value;
        }

        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetManagedInstanceErrataFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedInstanceErrataFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedInstanceErrataFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public Input<string> ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// A filter to return resources that may partially match the erratum name given.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        [Input("names")]
        private InputList<string>? _names;

        /// <summary>
        /// The assigned erratum name. It's unique and not changeable.  Example: `ELSA-2020-5804`
        /// </summary>
        public InputList<string> Names
        {
            get => _names ?? (_names = new InputList<string>());
            set => _names = value;
        }

        public GetManagedInstanceErrataInvokeArgs()
        {
        }
        public static new GetManagedInstanceErrataInvokeArgs Empty => new GetManagedInstanceErrataInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedInstanceErrataResult
    {
        public readonly ImmutableArray<string> ClassificationTypes;
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetManagedInstanceErrataFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of managed_instance_erratum_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceErrataManagedInstanceErratumSummaryCollectionResult> ManagedInstanceErratumSummaryCollections;
        public readonly string ManagedInstanceId;
        public readonly string? NameContains;
        /// <summary>
        /// The name of the software package.
        /// </summary>
        public readonly ImmutableArray<string> Names;

        [OutputConstructor]
        private GetManagedInstanceErrataResult(
            ImmutableArray<string> classificationTypes,

            string? compartmentId,

            ImmutableArray<Outputs.GetManagedInstanceErrataFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetManagedInstanceErrataManagedInstanceErratumSummaryCollectionResult> managedInstanceErratumSummaryCollections,

            string managedInstanceId,

            string? nameContains,

            ImmutableArray<string> names)
        {
            ClassificationTypes = classificationTypes;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ManagedInstanceErratumSummaryCollections = managedInstanceErratumSummaryCollections;
            ManagedInstanceId = managedInstanceId;
            NameContains = nameContains;
            Names = names;
        }
    }
}
