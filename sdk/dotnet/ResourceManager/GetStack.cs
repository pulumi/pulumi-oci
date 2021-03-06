// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceManager
{
    public static class GetStack
    {
        /// <summary>
        /// This data source provides details about a specific Stack resource in Oracle Cloud Infrastructure Resource Manager service.
        /// 
        /// Gets a stack using the stack ID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testStack = Output.Create(Oci.ResourceManager.GetStack.InvokeAsync(new Oci.ResourceManager.GetStackArgs
        ///         {
        ///             StackId = oci_resourcemanager_stack.Test_stack.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetStackResult> InvokeAsync(GetStackArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetStackResult>("oci:ResourceManager/getStack:getStack", args ?? new GetStackArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Stack resource in Oracle Cloud Infrastructure Resource Manager service.
        /// 
        /// Gets a stack using the stack ID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testStack = Output.Create(Oci.ResourceManager.GetStack.InvokeAsync(new Oci.ResourceManager.GetStackArgs
        ///         {
        ///             StackId = oci_resourcemanager_stack.Test_stack.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetStackResult> Invoke(GetStackInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetStackResult>("oci:ResourceManager/getStack:getStack", args ?? new GetStackInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetStackArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
        /// </summary>
        [Input("stackId", required: true)]
        public string StackId { get; set; } = null!;

        public GetStackArgs()
        {
        }
    }

    public sealed class GetStackInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
        /// </summary>
        [Input("stackId", required: true)]
        public Input<string> StackId { get; set; } = null!;

        public GetStackInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetStackResult
    {
        /// <summary>
        /// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetStackConfigSourceResult> ConfigSources;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// General description of the stack.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Human-readable display name for the stack.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags associated with this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string StackId;
        /// <summary>
        /// The current lifecycle state of the stack.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time at which the stack was created.
        /// </summary>
        public readonly string TimeCreated;
        public readonly ImmutableDictionary<string, object> Variables;

        [OutputConstructor]
        private GetStackResult(
            string compartmentId,

            ImmutableArray<Outputs.GetStackConfigSourceResult> configSources,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string stackId,

            string state,

            string timeCreated,

            ImmutableDictionary<string, object> variables)
        {
            CompartmentId = compartmentId;
            ConfigSources = configSources;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            StackId = stackId;
            State = state;
            TimeCreated = timeCreated;
            Variables = variables;
        }
    }
}
