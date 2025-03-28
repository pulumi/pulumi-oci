// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement
{
    public static class GetSoftwareSources
    {
        /// <summary>
        /// This data source provides the list of Software Sources in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Returns a list of all Software Sources.
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
        ///     var testSoftwareSources = Oci.OsManagement.GetSoftwareSources.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = softwareSourceDisplayName,
        ///         State = softwareSourceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSoftwareSourcesResult> InvokeAsync(GetSoftwareSourcesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSoftwareSourcesResult>("oci:OsManagement/getSoftwareSources:getSoftwareSources", args ?? new GetSoftwareSourcesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Software Sources in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Returns a list of all Software Sources.
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
        ///     var testSoftwareSources = Oci.OsManagement.GetSoftwareSources.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = softwareSourceDisplayName,
        ///         State = softwareSourceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourcesResult> Invoke(GetSoftwareSourcesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourcesResult>("oci:OsManagement/getSoftwareSources:getSoftwareSources", args ?? new GetSoftwareSourcesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Software Sources in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Returns a list of all Software Sources.
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
        ///     var testSoftwareSources = Oci.OsManagement.GetSoftwareSources.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = softwareSourceDisplayName,
        ///         State = softwareSourceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourcesResult> Invoke(GetSoftwareSourcesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourcesResult>("oci:OsManagement/getSoftwareSources:getSoftwareSources", args ?? new GetSoftwareSourcesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSoftwareSourcesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetSoftwareSourcesFilterArgs>? _filters;
        public List<Inputs.GetSoftwareSourcesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSoftwareSourcesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The current lifecycle state for the object.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetSoftwareSourcesArgs()
        {
        }
        public static new GetSoftwareSourcesArgs Empty => new GetSoftwareSourcesArgs();
    }

    public sealed class GetSoftwareSourcesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetSoftwareSourcesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSoftwareSourcesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSoftwareSourcesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The current lifecycle state for the object.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetSoftwareSourcesInvokeArgs()
        {
        }
        public static new GetSoftwareSourcesInvokeArgs Empty => new GetSoftwareSourcesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSoftwareSourcesResult
    {
        /// <summary>
        /// OCID for the Compartment
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// User friendly name for the software source
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetSoftwareSourcesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of software_sources.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSoftwareSourcesSoftwareSourceResult> SoftwareSources;
        /// <summary>
        /// The current state of the Software Source.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetSoftwareSourcesResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetSoftwareSourcesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetSoftwareSourcesSoftwareSourceResult> softwareSources,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            SoftwareSources = softwareSources;
            State = state;
        }
    }
}
