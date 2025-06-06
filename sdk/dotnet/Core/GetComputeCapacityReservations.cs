// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeCapacityReservations
    {
        /// <summary>
        /// This data source provides the list of Compute Capacity Reservations in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute capacity reservations that match the specified criteria and compartment.
        /// 
        /// You can limit the list by specifying a compute capacity reservation display name 
        /// (the list will include all the identically-named compute capacity reservations in the compartment).
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
        ///     var testComputeCapacityReservations = Oci.Core.GetComputeCapacityReservations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeCapacityReservationAvailabilityDomain,
        ///         DisplayName = computeCapacityReservationDisplayName,
        ///         State = computeCapacityReservationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetComputeCapacityReservationsResult> InvokeAsync(GetComputeCapacityReservationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetComputeCapacityReservationsResult>("oci:Core/getComputeCapacityReservations:getComputeCapacityReservations", args ?? new GetComputeCapacityReservationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Capacity Reservations in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute capacity reservations that match the specified criteria and compartment.
        /// 
        /// You can limit the list by specifying a compute capacity reservation display name 
        /// (the list will include all the identically-named compute capacity reservations in the compartment).
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
        ///     var testComputeCapacityReservations = Oci.Core.GetComputeCapacityReservations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeCapacityReservationAvailabilityDomain,
        ///         DisplayName = computeCapacityReservationDisplayName,
        ///         State = computeCapacityReservationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeCapacityReservationsResult> Invoke(GetComputeCapacityReservationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeCapacityReservationsResult>("oci:Core/getComputeCapacityReservations:getComputeCapacityReservations", args ?? new GetComputeCapacityReservationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Capacity Reservations in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the compute capacity reservations that match the specified criteria and compartment.
        /// 
        /// You can limit the list by specifying a compute capacity reservation display name 
        /// (the list will include all the identically-named compute capacity reservations in the compartment).
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
        ///     var testComputeCapacityReservations = Oci.Core.GetComputeCapacityReservations.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = computeCapacityReservationAvailabilityDomain,
        ///         DisplayName = computeCapacityReservationDisplayName,
        ///         State = computeCapacityReservationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeCapacityReservationsResult> Invoke(GetComputeCapacityReservationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeCapacityReservationsResult>("oci:Core/getComputeCapacityReservations:getComputeCapacityReservations", args ?? new GetComputeCapacityReservationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetComputeCapacityReservationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeCapacityReservationsFilterArgs>? _filters;
        public List<Inputs.GetComputeCapacityReservationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeCapacityReservationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetComputeCapacityReservationsArgs()
        {
        }
        public static new GetComputeCapacityReservationsArgs Empty => new GetComputeCapacityReservationsArgs();
    }

    public sealed class GetComputeCapacityReservationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetComputeCapacityReservationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetComputeCapacityReservationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetComputeCapacityReservationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetComputeCapacityReservationsInvokeArgs()
        {
        }
        public static new GetComputeCapacityReservationsInvokeArgs Empty => new GetComputeCapacityReservationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetComputeCapacityReservationsResult
    {
        /// <summary>
        /// The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of compute_capacity_reservations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeCapacityReservationsComputeCapacityReservationResult> ComputeCapacityReservations;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetComputeCapacityReservationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the compute capacity reservation.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetComputeCapacityReservationsResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetComputeCapacityReservationsComputeCapacityReservationResult> computeCapacityReservations,

            string? displayName,

            ImmutableArray<Outputs.GetComputeCapacityReservationsFilterResult> filters,

            string id,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ComputeCapacityReservations = computeCapacityReservations;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
