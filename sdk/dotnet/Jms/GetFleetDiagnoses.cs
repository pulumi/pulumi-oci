// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetFleetDiagnoses
    {
        /// <summary>
        /// This data source provides the list of Fleet Diagnoses in Oracle Cloud Infrastructure Jms service.
        /// 
        /// List potential diagnoses that would put a fleet into FAILED or NEEDS_ATTENTION lifecycle state.
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
        ///     var testFleetDiagnoses = Oci.Jms.GetFleetDiagnoses.Invoke(new()
        ///     {
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFleetDiagnosesResult> InvokeAsync(GetFleetDiagnosesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFleetDiagnosesResult>("oci:Jms/getFleetDiagnoses:getFleetDiagnoses", args ?? new GetFleetDiagnosesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fleet Diagnoses in Oracle Cloud Infrastructure Jms service.
        /// 
        /// List potential diagnoses that would put a fleet into FAILED or NEEDS_ATTENTION lifecycle state.
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
        ///     var testFleetDiagnoses = Oci.Jms.GetFleetDiagnoses.Invoke(new()
        ///     {
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFleetDiagnosesResult> Invoke(GetFleetDiagnosesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFleetDiagnosesResult>("oci:Jms/getFleetDiagnoses:getFleetDiagnoses", args ?? new GetFleetDiagnosesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fleet Diagnoses in Oracle Cloud Infrastructure Jms service.
        /// 
        /// List potential diagnoses that would put a fleet into FAILED or NEEDS_ATTENTION lifecycle state.
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
        ///     var testFleetDiagnoses = Oci.Jms.GetFleetDiagnoses.Invoke(new()
        ///     {
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFleetDiagnosesResult> Invoke(GetFleetDiagnosesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFleetDiagnosesResult>("oci:Jms/getFleetDiagnoses:getFleetDiagnoses", args ?? new GetFleetDiagnosesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFleetDiagnosesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetFleetDiagnosesFilterArgs>? _filters;
        public List<Inputs.GetFleetDiagnosesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFleetDiagnosesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public string FleetId { get; set; } = null!;

        public GetFleetDiagnosesArgs()
        {
        }
        public static new GetFleetDiagnosesArgs Empty => new GetFleetDiagnosesArgs();
    }

    public sealed class GetFleetDiagnosesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetFleetDiagnosesFilterInputArgs>? _filters;
        public InputList<Inputs.GetFleetDiagnosesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFleetDiagnosesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public Input<string> FleetId { get; set; } = null!;

        public GetFleetDiagnosesInvokeArgs()
        {
        }
        public static new GetFleetDiagnosesInvokeArgs Empty => new GetFleetDiagnosesInvokeArgs();
    }


    [OutputType]
    public sealed class GetFleetDiagnosesResult
    {
        public readonly ImmutableArray<Outputs.GetFleetDiagnosesFilterResult> Filters;
        /// <summary>
        /// The list of fleet_diagnosis_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetDiagnosesFleetDiagnosisCollectionResult> FleetDiagnosisCollections;
        public readonly string FleetId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetFleetDiagnosesResult(
            ImmutableArray<Outputs.GetFleetDiagnosesFilterResult> filters,

            ImmutableArray<Outputs.GetFleetDiagnosesFleetDiagnosisCollectionResult> fleetDiagnosisCollections,

            string fleetId,

            string id)
        {
            Filters = filters;
            FleetDiagnosisCollections = fleetDiagnosisCollections;
            FleetId = fleetId;
            Id = id;
        }
    }
}
