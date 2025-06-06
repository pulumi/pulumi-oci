// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OperatorAccessControl
{
    public static class GetControls
    {
        /// <summary>
        /// This data source provides the list of Operator Controls in Oracle Cloud Infrastructure Operator Access Control service.
        /// 
        /// Lists the operator controls in the compartment.
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
        ///     var testOperatorControls = Oci.OperatorAccessControl.GetControls.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = operatorControlDisplayName,
        ///         ResourceType = operatorControlResourceType,
        ///         State = operatorControlState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetControlsResult> InvokeAsync(GetControlsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetControlsResult>("oci:OperatorAccessControl/getControls:getControls", args ?? new GetControlsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Operator Controls in Oracle Cloud Infrastructure Operator Access Control service.
        /// 
        /// Lists the operator controls in the compartment.
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
        ///     var testOperatorControls = Oci.OperatorAccessControl.GetControls.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = operatorControlDisplayName,
        ///         ResourceType = operatorControlResourceType,
        ///         State = operatorControlState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetControlsResult> Invoke(GetControlsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetControlsResult>("oci:OperatorAccessControl/getControls:getControls", args ?? new GetControlsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Operator Controls in Oracle Cloud Infrastructure Operator Access Control service.
        /// 
        /// Lists the operator controls in the compartment.
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
        ///     var testOperatorControls = Oci.OperatorAccessControl.GetControls.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = operatorControlDisplayName,
        ///         ResourceType = operatorControlResourceType,
        ///         State = operatorControlState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetControlsResult> Invoke(GetControlsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetControlsResult>("oci:OperatorAccessControl/getControls:getControls", args ?? new GetControlsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetControlsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return OperatorControl that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetControlsFilterArgs>? _filters;
        public List<Inputs.GetControlsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetControlsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only lists of resources that match the entire given service type.
        /// </summary>
        [Input("resourceType")]
        public string? ResourceType { get; set; }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given OperatorControl lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetControlsArgs()
        {
        }
        public static new GetControlsArgs Empty => new GetControlsArgs();
    }

    public sealed class GetControlsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return OperatorControl that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetControlsFilterInputArgs>? _filters;
        public InputList<Inputs.GetControlsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetControlsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only lists of resources that match the entire given service type.
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given OperatorControl lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetControlsInvokeArgs()
        {
        }
        public static new GetControlsInvokeArgs Empty => new GetControlsInvokeArgs();
    }


    [OutputType]
    public sealed class GetControlsResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the operator control.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetControlsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of operator_control_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetControlsOperatorControlCollectionResult> OperatorControlCollections;
        /// <summary>
        /// resourceType for which the OperatorControl is applicable
        /// </summary>
        public readonly string? ResourceType;
        /// <summary>
        /// The current lifecycle state of the operator control.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetControlsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetControlsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetControlsOperatorControlCollectionResult> operatorControlCollections,

            string? resourceType,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OperatorControlCollections = operatorControlCollections;
            ResourceType = resourceType;
            State = state;
        }
    }
}
