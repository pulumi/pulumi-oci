// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Queue
{
    public static class GetQueues
    {
        /// <summary>
        /// This data source provides the list of Queues in Oracle Cloud Infrastructure Queue service.
        /// 
        /// Returns a list of Queues.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testQueues = Oci.Queue.GetQueues.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Queue_display_name,
        ///         Id = @var.Queue_id,
        ///         State = @var.Queue_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetQueuesResult> InvokeAsync(GetQueuesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetQueuesResult>("oci:Queue/getQueues:getQueues", args ?? new GetQueuesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Queues in Oracle Cloud Infrastructure Queue service.
        /// 
        /// Returns a list of Queues.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testQueues = Oci.Queue.GetQueues.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Queue_display_name,
        ///         Id = @var.Queue_id,
        ///         State = @var.Queue_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetQueuesResult> Invoke(GetQueuesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetQueuesResult>("oci:Queue/getQueues:getQueues", args ?? new GetQueuesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetQueuesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetQueuesFilterArgs>? _filters;
        public List<Inputs.GetQueuesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetQueuesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique Queue identifier
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources their lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetQueuesArgs()
        {
        }
        public static new GetQueuesArgs Empty => new GetQueuesArgs();
    }

    public sealed class GetQueuesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetQueuesFilterInputArgs>? _filters;
        public InputList<Inputs.GetQueuesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetQueuesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique Queue identifier
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only resources their lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetQueuesInvokeArgs()
        {
        }
        public static new GetQueuesInvokeArgs Empty => new GetQueuesInvokeArgs();
    }


    [OutputType]
    public sealed class GetQueuesResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Queue Identifier, can be renamed
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetQueuesFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of queue_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetQueuesQueueCollectionResult> QueueCollections;
        /// <summary>
        /// The current state of the Queue.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetQueuesResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetQueuesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetQueuesQueueCollectionResult> queueCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            QueueCollections = queueCollections;
            State = state;
        }
    }
}