// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetOneoffPatches
    {
        /// <summary>
        /// This data source provides the list of Oneoff Patches in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists one-off patches in the specified compartment.
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
        ///     var testOneoffPatches = Oci.Database.GetOneoffPatches.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = oneoffPatchDisplayName,
        ///         State = oneoffPatchState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOneoffPatchesResult> InvokeAsync(GetOneoffPatchesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOneoffPatchesResult>("oci:Database/getOneoffPatches:getOneoffPatches", args ?? new GetOneoffPatchesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oneoff Patches in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists one-off patches in the specified compartment.
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
        ///     var testOneoffPatches = Oci.Database.GetOneoffPatches.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = oneoffPatchDisplayName,
        ///         State = oneoffPatchState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOneoffPatchesResult> Invoke(GetOneoffPatchesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOneoffPatchesResult>("oci:Database/getOneoffPatches:getOneoffPatches", args ?? new GetOneoffPatchesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oneoff Patches in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists one-off patches in the specified compartment.
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
        ///     var testOneoffPatches = Oci.Database.GetOneoffPatches.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = oneoffPatchDisplayName,
        ///         State = oneoffPatchState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOneoffPatchesResult> Invoke(GetOneoffPatchesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOneoffPatchesResult>("oci:Database/getOneoffPatches:getOneoffPatches", args ?? new GetOneoffPatchesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOneoffPatchesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetOneoffPatchesFilterArgs>? _filters;
        public List<Inputs.GetOneoffPatchesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOneoffPatchesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetOneoffPatchesArgs()
        {
        }
        public static new GetOneoffPatchesArgs Empty => new GetOneoffPatchesArgs();
    }

    public sealed class GetOneoffPatchesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOneoffPatchesFilterInputArgs>? _filters;
        public InputList<Inputs.GetOneoffPatchesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOneoffPatchesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetOneoffPatchesInvokeArgs()
        {
        }
        public static new GetOneoffPatchesInvokeArgs Empty => new GetOneoffPatchesInvokeArgs();
    }


    [OutputType]
    public sealed class GetOneoffPatchesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// One-off patch name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOneoffPatchesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of oneoff_patches.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOneoffPatchesOneoffPatchResult> OneoffPatches;
        /// <summary>
        /// The current state of the one-off patch.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetOneoffPatchesResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetOneoffPatchesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetOneoffPatchesOneoffPatchResult> oneoffPatches,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OneoffPatches = oneoffPatches;
            State = state;
        }
    }
}
