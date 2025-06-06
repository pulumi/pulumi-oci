// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDbPreviewVersions
    {
        /// <summary>
        /// This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
        /// Autonomous Database Serverless (https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html) databases.
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
        ///     var testAutonomousDbPreviewVersions = Oci.Database.GetAutonomousDbPreviewVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousDbPreviewVersionsResult> InvokeAsync(GetAutonomousDbPreviewVersionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDbPreviewVersionsResult>("oci:Database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", args ?? new GetAutonomousDbPreviewVersionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
        /// Autonomous Database Serverless (https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html) databases.
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
        ///     var testAutonomousDbPreviewVersions = Oci.Database.GetAutonomousDbPreviewVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDbPreviewVersionsResult> Invoke(GetAutonomousDbPreviewVersionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDbPreviewVersionsResult>("oci:Database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", args ?? new GetAutonomousDbPreviewVersionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
        /// Autonomous Database Serverless (https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html) databases.
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
        ///     var testAutonomousDbPreviewVersions = Oci.Database.GetAutonomousDbPreviewVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDbPreviewVersionsResult> Invoke(GetAutonomousDbPreviewVersionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDbPreviewVersionsResult>("oci:Database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", args ?? new GetAutonomousDbPreviewVersionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDbPreviewVersionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs>? _filters;
        public List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs>());
            set => _filters = value;
        }

        public GetAutonomousDbPreviewVersionsArgs()
        {
        }
        public static new GetAutonomousDbPreviewVersionsArgs Empty => new GetAutonomousDbPreviewVersionsArgs();
    }

    public sealed class GetAutonomousDbPreviewVersionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetAutonomousDbPreviewVersionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAutonomousDbPreviewVersionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAutonomousDbPreviewVersionsFilterInputArgs>());
            set => _filters = value;
        }

        public GetAutonomousDbPreviewVersionsInvokeArgs()
        {
        }
        public static new GetAutonomousDbPreviewVersionsInvokeArgs Empty => new GetAutonomousDbPreviewVersionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousDbPreviewVersionsResult
    {
        /// <summary>
        /// The list of autonomous_db_preview_versions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersionResult> AutonomousDbPreviewVersions;
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetAutonomousDbPreviewVersionsResult(
            ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersionResult> autonomousDbPreviewVersions,

            string compartmentId,

            ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsFilterResult> filters,

            string id)
        {
            AutonomousDbPreviewVersions = autonomousDbPreviewVersions;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
        }
    }
}
