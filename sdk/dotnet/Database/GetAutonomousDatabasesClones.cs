// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabasesClones
    {
        /// <summary>
        /// This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Autonomous Database clones for the specified Autonomous Database.
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
        ///     var testAutonomousDatabasesClones = Oci.Database.GetAutonomousDatabasesClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///         CompartmentId = compartmentId,
        ///         CloneType = autonomousDatabasesCloneCloneType,
        ///         DisplayName = autonomousDatabasesCloneDisplayName,
        ///         State = autonomousDatabasesCloneState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousDatabasesClonesResult> InvokeAsync(GetAutonomousDatabasesClonesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabasesClonesResult>("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", args ?? new GetAutonomousDatabasesClonesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Autonomous Database clones for the specified Autonomous Database.
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
        ///     var testAutonomousDatabasesClones = Oci.Database.GetAutonomousDatabasesClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///         CompartmentId = compartmentId,
        ///         CloneType = autonomousDatabasesCloneCloneType,
        ///         DisplayName = autonomousDatabasesCloneDisplayName,
        ///         State = autonomousDatabasesCloneState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabasesClonesResult> Invoke(GetAutonomousDatabasesClonesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabasesClonesResult>("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", args ?? new GetAutonomousDatabasesClonesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Autonomous Database clones for the specified Autonomous Database.
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
        ///     var testAutonomousDatabasesClones = Oci.Database.GetAutonomousDatabasesClones.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///         CompartmentId = compartmentId,
        ///         CloneType = autonomousDatabasesCloneCloneType,
        ///         DisplayName = autonomousDatabasesCloneDisplayName,
        ///         State = autonomousDatabasesCloneState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabasesClonesResult> Invoke(GetAutonomousDatabasesClonesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabasesClonesResult>("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", args ?? new GetAutonomousDatabasesClonesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDatabasesClonesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public string AutonomousDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given clone type exactly.
        /// </summary>
        [Input("cloneType")]
        public string? CloneType { get; set; }

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAutonomousDatabasesClonesFilterArgs>? _filters;
        public List<Inputs.GetAutonomousDatabasesClonesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousDatabasesClonesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAutonomousDatabasesClonesArgs()
        {
        }
        public static new GetAutonomousDatabasesClonesArgs Empty => new GetAutonomousDatabasesClonesArgs();
    }

    public sealed class GetAutonomousDatabasesClonesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public Input<string> AutonomousDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given clone type exactly.
        /// </summary>
        [Input("cloneType")]
        public Input<string>? CloneType { get; set; }

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAutonomousDatabasesClonesFilterInputArgs>? _filters;
        public InputList<Inputs.GetAutonomousDatabasesClonesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAutonomousDatabasesClonesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetAutonomousDatabasesClonesInvokeArgs()
        {
        }
        public static new GetAutonomousDatabasesClonesInvokeArgs Empty => new GetAutonomousDatabasesClonesInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousDatabasesClonesResult
    {
        public readonly string AutonomousDatabaseId;
        /// <summary>
        /// The list of autonomous_databases.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousDatabasesClonesAutonomousDatabaseResult> AutonomousDatabases;
        public readonly string? CloneType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-friendly name for the Autonomous Database. The name does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAutonomousDatabasesClonesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the Autonomous Database.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAutonomousDatabasesClonesResult(
            string autonomousDatabaseId,

            ImmutableArray<Outputs.GetAutonomousDatabasesClonesAutonomousDatabaseResult> autonomousDatabases,

            string? cloneType,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetAutonomousDatabasesClonesFilterResult> filters,

            string id,

            string? state)
        {
            AutonomousDatabaseId = autonomousDatabaseId;
            AutonomousDatabases = autonomousDatabases;
            CloneType = cloneType;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
