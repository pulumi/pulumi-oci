// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetImportableComputeEntities
    {
        /// <summary>
        /// This data source provides the list of Importable Compute Entities in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of available compute intances running cloud agent to add a new hostInsight.  An Compute entity is "available"
        /// and will be shown if all the following conditions are true:
        ///    1. Compute is running OCA
        ///    2. Oracle Cloud Infrastructure Management Agent is not enabled or If Oracle Cloud Infrastructure Management Agent is enabled
        ///       2.1 The agent OCID is not already being used for an existing hostInsight.
        ///       2.2 The agent availabilityStatus = 'ACTIVE'
        ///       2.3 The agent lifecycleState = 'ACTIVE'
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
        ///     var testImportableComputeEntities = Oci.Opsi.GetImportableComputeEntities.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetImportableComputeEntitiesResult> InvokeAsync(GetImportableComputeEntitiesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetImportableComputeEntitiesResult>("oci:Opsi/getImportableComputeEntities:getImportableComputeEntities", args ?? new GetImportableComputeEntitiesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Importable Compute Entities in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of available compute intances running cloud agent to add a new hostInsight.  An Compute entity is "available"
        /// and will be shown if all the following conditions are true:
        ///    1. Compute is running OCA
        ///    2. Oracle Cloud Infrastructure Management Agent is not enabled or If Oracle Cloud Infrastructure Management Agent is enabled
        ///       2.1 The agent OCID is not already being used for an existing hostInsight.
        ///       2.2 The agent availabilityStatus = 'ACTIVE'
        ///       2.3 The agent lifecycleState = 'ACTIVE'
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
        ///     var testImportableComputeEntities = Oci.Opsi.GetImportableComputeEntities.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetImportableComputeEntitiesResult> Invoke(GetImportableComputeEntitiesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetImportableComputeEntitiesResult>("oci:Opsi/getImportableComputeEntities:getImportableComputeEntities", args ?? new GetImportableComputeEntitiesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetImportableComputeEntitiesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        public GetImportableComputeEntitiesArgs()
        {
        }
        public static new GetImportableComputeEntitiesArgs Empty => new GetImportableComputeEntitiesArgs();
    }

    public sealed class GetImportableComputeEntitiesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        public GetImportableComputeEntitiesInvokeArgs()
        {
        }
        public static new GetImportableComputeEntitiesInvokeArgs Empty => new GetImportableComputeEntitiesInvokeArgs();
    }


    [OutputType]
    public sealed class GetImportableComputeEntitiesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Array of importable compute entity objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetImportableComputeEntitiesItemResult> Items;

        [OutputConstructor]
        private GetImportableComputeEntitiesResult(
            string compartmentId,

            string id,

            ImmutableArray<Outputs.GetImportableComputeEntitiesItemResult> items)
        {
            CompartmentId = compartmentId;
            Id = id;
            Items = items;
        }
    }
}