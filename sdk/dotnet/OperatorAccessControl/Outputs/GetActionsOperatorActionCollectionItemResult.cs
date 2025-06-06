// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OperatorAccessControl.Outputs
{

    [OutputType]
    public sealed class GetActionsOperatorActionCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Name of the infrastructure layer associated with the operator action.
        /// </summary>
        public readonly string Component;
        /// <summary>
        /// Display Name of the operator action.
        /// </summary>
        public readonly string CustomerDisplayName;
        /// <summary>
        /// Description of the operator action in terms of associated risk profile, and characteristics of the operating system commands made available to the operator under this operator action.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Unique Oracle assigned identifier for the operator action.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Fine grained properties associated with the operator control.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetActionsOperatorActionCollectionItemPropertyResult> Properties;
        /// <summary>
        /// A filter to return only lists of resources that match the entire given service type.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// A filter to return only resources whose lifecycleState matches the given OperatorAction lifecycleState.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetActionsOperatorActionCollectionItemResult(
            string? compartmentId,

            string component,

            string customerDisplayName,

            string description,

            string id,

            string name,

            ImmutableArray<Outputs.GetActionsOperatorActionCollectionItemPropertyResult> properties,

            string resourceType,

            string? state)
        {
            CompartmentId = compartmentId;
            Component = component;
            CustomerDisplayName = customerDisplayName;
            Description = description;
            Id = id;
            Name = name;
            Properties = properties;
            ResourceType = resourceType;
            State = state;
        }
    }
}
