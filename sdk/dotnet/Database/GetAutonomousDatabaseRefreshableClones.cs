// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabaseRefreshableClones
    {
        /// <summary>
        /// This data source provides the list of Autonomous Database Refreshable Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the OCIDs of the Autonomous Database local and connected remote refreshable clones with the region where they exist for the specified source database.
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
        ///     var testAutonomousDatabaseRefreshableClones = Oci.Database.GetAutonomousDatabaseRefreshableClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousDatabaseRefreshableClonesResult> InvokeAsync(GetAutonomousDatabaseRefreshableClonesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabaseRefreshableClonesResult>("oci:Database/getAutonomousDatabaseRefreshableClones:getAutonomousDatabaseRefreshableClones", args ?? new GetAutonomousDatabaseRefreshableClonesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Database Refreshable Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the OCIDs of the Autonomous Database local and connected remote refreshable clones with the region where they exist for the specified source database.
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
        ///     var testAutonomousDatabaseRefreshableClones = Oci.Database.GetAutonomousDatabaseRefreshableClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseRefreshableClonesResult> Invoke(GetAutonomousDatabaseRefreshableClonesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseRefreshableClonesResult>("oci:Database/getAutonomousDatabaseRefreshableClones:getAutonomousDatabaseRefreshableClones", args ?? new GetAutonomousDatabaseRefreshableClonesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Database Refreshable Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the OCIDs of the Autonomous Database local and connected remote refreshable clones with the region where they exist for the specified source database.
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
        ///     var testAutonomousDatabaseRefreshableClones = Oci.Database.GetAutonomousDatabaseRefreshableClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseRefreshableClonesResult> Invoke(GetAutonomousDatabaseRefreshableClonesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseRefreshableClonesResult>("oci:Database/getAutonomousDatabaseRefreshableClones:getAutonomousDatabaseRefreshableClones", args ?? new GetAutonomousDatabaseRefreshableClonesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDatabaseRefreshableClonesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public string AutonomousDatabaseId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetAutonomousDatabaseRefreshableClonesFilterArgs>? _filters;
        public List<Inputs.GetAutonomousDatabaseRefreshableClonesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousDatabaseRefreshableClonesFilterArgs>());
            set => _filters = value;
        }

        public GetAutonomousDatabaseRefreshableClonesArgs()
        {
        }
        public static new GetAutonomousDatabaseRefreshableClonesArgs Empty => new GetAutonomousDatabaseRefreshableClonesArgs();
    }

    public sealed class GetAutonomousDatabaseRefreshableClonesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public Input<string> AutonomousDatabaseId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetAutonomousDatabaseRefreshableClonesFilterInputArgs>? _filters;
        public InputList<Inputs.GetAutonomousDatabaseRefreshableClonesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAutonomousDatabaseRefreshableClonesFilterInputArgs>());
            set => _filters = value;
        }

        public GetAutonomousDatabaseRefreshableClonesInvokeArgs()
        {
        }
        public static new GetAutonomousDatabaseRefreshableClonesInvokeArgs Empty => new GetAutonomousDatabaseRefreshableClonesInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousDatabaseRefreshableClonesResult
    {
        public readonly string AutonomousDatabaseId;
        public readonly ImmutableArray<Outputs.GetAutonomousDatabaseRefreshableClonesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of refreshable_clone_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousDatabaseRefreshableClonesRefreshableCloneCollectionResult> RefreshableCloneCollections;

        [OutputConstructor]
        private GetAutonomousDatabaseRefreshableClonesResult(
            string autonomousDatabaseId,

            ImmutableArray<Outputs.GetAutonomousDatabaseRefreshableClonesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetAutonomousDatabaseRefreshableClonesRefreshableCloneCollectionResult> refreshableCloneCollections)
        {
            AutonomousDatabaseId = autonomousDatabaseId;
            Filters = filters;
            Id = id;
            RefreshableCloneCollections = refreshableCloneCollections;
        }
    }
}
