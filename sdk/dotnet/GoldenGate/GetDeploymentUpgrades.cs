// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetDeploymentUpgrades
    {
        /// <summary>
        /// This data source provides the list of Deployment Upgrades in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the Deployment Upgrades in a compartment.
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
        ///     var testDeploymentUpgrades = Oci.GoldenGate.GetDeploymentUpgrades.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///         DisplayName = @var.Deployment_upgrade_display_name,
        ///         State = @var.Deployment_upgrade_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeploymentUpgradesResult> InvokeAsync(GetDeploymentUpgradesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentUpgradesResult>("oci:GoldenGate/getDeploymentUpgrades:getDeploymentUpgrades", args ?? new GetDeploymentUpgradesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Deployment Upgrades in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the Deployment Upgrades in a compartment.
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
        ///     var testDeploymentUpgrades = Oci.GoldenGate.GetDeploymentUpgrades.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///         DisplayName = @var.Deployment_upgrade_display_name,
        ///         State = @var.Deployment_upgrade_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDeploymentUpgradesResult> Invoke(GetDeploymentUpgradesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDeploymentUpgradesResult>("oci:GoldenGate/getDeploymentUpgrades:getDeploymentUpgrades", args ?? new GetDeploymentUpgradesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeploymentUpgradesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The ID of the deployment in which to list resources.
        /// </summary>
        [Input("deploymentId")]
        public string? DeploymentId { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeploymentUpgradesFilterArgs>? _filters;
        public List<Inputs.GetDeploymentUpgradesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeploymentUpgradesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDeploymentUpgradesArgs()
        {
        }
        public static new GetDeploymentUpgradesArgs Empty => new GetDeploymentUpgradesArgs();
    }

    public sealed class GetDeploymentUpgradesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The ID of the deployment in which to list resources.
        /// </summary>
        [Input("deploymentId")]
        public Input<string>? DeploymentId { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDeploymentUpgradesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDeploymentUpgradesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDeploymentUpgradesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetDeploymentUpgradesInvokeArgs()
        {
        }
        public static new GetDeploymentUpgradesInvokeArgs Empty => new GetDeploymentUpgradesInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeploymentUpgradesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        /// </summary>
        public readonly string? DeploymentId;
        /// <summary>
        /// The list of deployment_upgrade_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentUpgradesDeploymentUpgradeCollectionResult> DeploymentUpgradeCollections;
        /// <summary>
        /// An object's Display Name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeploymentUpgradesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Possible lifecycle states.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDeploymentUpgradesResult(
            string compartmentId,

            string? deploymentId,

            ImmutableArray<Outputs.GetDeploymentUpgradesDeploymentUpgradeCollectionResult> deploymentUpgradeCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDeploymentUpgradesFilterResult> filters,

            string id,

            string? state)
        {
            CompartmentId = compartmentId;
            DeploymentId = deploymentId;
            DeploymentUpgradeCollections = deploymentUpgradeCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}