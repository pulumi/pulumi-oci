// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf
{
    public static class GetFirewalls
    {
        /// <summary>
        /// This data source provides the list of Web App Firewalls in Oracle Cloud Infrastructure Waf service.
        /// 
        /// Gets a list of all WebAppFirewalls in a compartment.
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
        ///     var testWebAppFirewalls = Oci.Waf.GetFirewalls.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Web_app_firewall_display_name,
        ///         Id = @var.Web_app_firewall_id,
        ///         States = @var.Web_app_firewall_state,
        ///         WebAppFirewallPolicyId = oci_waf_web_app_firewall_policy.Test_web_app_firewall_policy.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFirewallsResult> InvokeAsync(GetFirewallsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFirewallsResult>("oci:Waf/getFirewalls:getFirewalls", args ?? new GetFirewallsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Web App Firewalls in Oracle Cloud Infrastructure Waf service.
        /// 
        /// Gets a list of all WebAppFirewalls in a compartment.
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
        ///     var testWebAppFirewalls = Oci.Waf.GetFirewalls.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Web_app_firewall_display_name,
        ///         Id = @var.Web_app_firewall_id,
        ///         States = @var.Web_app_firewall_state,
        ///         WebAppFirewallPolicyId = oci_waf_web_app_firewall_policy.Test_web_app_firewall_policy.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFirewallsResult> Invoke(GetFirewallsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetFirewallsResult>("oci:Waf/getFirewalls:getFirewalls", args ?? new GetFirewallsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFirewallsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetFirewallsFilterArgs>? _filters;
        public List<Inputs.GetFirewallsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFirewallsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the WebAppFirewall with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        [Input("states")]
        private List<string>? _states;

        /// <summary>
        /// A filter to return only resources that match the given lifecycleState.
        /// </summary>
        public List<string> States
        {
            get => _states ?? (_states = new List<string>());
            set => _states = value;
        }

        /// <summary>
        /// A filter to return only the WebAppFirewall with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppFirewallPolicy.
        /// </summary>
        [Input("webAppFirewallPolicyId")]
        public string? WebAppFirewallPolicyId { get; set; }

        public GetFirewallsArgs()
        {
        }
        public static new GetFirewallsArgs Empty => new GetFirewallsArgs();
    }

    public sealed class GetFirewallsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetFirewallsFilterInputArgs>? _filters;
        public InputList<Inputs.GetFirewallsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFirewallsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the WebAppFirewall with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        [Input("states")]
        private InputList<string>? _states;

        /// <summary>
        /// A filter to return only resources that match the given lifecycleState.
        /// </summary>
        public InputList<string> States
        {
            get => _states ?? (_states = new InputList<string>());
            set => _states = value;
        }

        /// <summary>
        /// A filter to return only the WebAppFirewall with the given [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of related WebAppFirewallPolicy.
        /// </summary>
        [Input("webAppFirewallPolicyId")]
        public Input<string>? WebAppFirewallPolicyId { get; set; }

        public GetFirewallsInvokeArgs()
        {
        }
        public static new GetFirewallsInvokeArgs Empty => new GetFirewallsInvokeArgs();
    }


    [OutputType]
    public sealed class GetFirewallsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// WebAppFirewall display name, can be renamed.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetFirewallsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the WebAppFirewall.
        /// </summary>
        public readonly ImmutableArray<string> States;
        /// <summary>
        /// The list of web_app_firewall_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFirewallsWebAppFirewallCollectionResult> WebAppFirewallCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
        /// </summary>
        public readonly string? WebAppFirewallPolicyId;

        [OutputConstructor]
        private GetFirewallsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetFirewallsFilterResult> filters,

            string? id,

            ImmutableArray<string> states,

            ImmutableArray<Outputs.GetFirewallsWebAppFirewallCollectionResult> webAppFirewallCollections,

            string? webAppFirewallPolicyId)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            States = states;
            WebAppFirewallCollections = webAppFirewallCollections;
            WebAppFirewallPolicyId = webAppFirewallPolicyId;
        }
    }
}