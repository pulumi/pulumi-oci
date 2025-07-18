// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement
{
    public static class GetCompliancePolicyRules
    {
        /// <summary>
        /// This data source provides the list of Compliance Policy Rules in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a list of Compliance policy rules in a compartment.
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
        ///     var testCompliancePolicyRules = Oci.FleetAppsManagement.GetCompliancePolicyRules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompliancePolicyId = testCompliancePolicy.Id,
        ///         DisplayName = compliancePolicyRuleDisplayName,
        ///         Id = compliancePolicyRuleId,
        ///         PatchName = testPatch.Name,
        ///         State = compliancePolicyRuleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetCompliancePolicyRulesResult> InvokeAsync(GetCompliancePolicyRulesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetCompliancePolicyRulesResult>("oci:FleetAppsManagement/getCompliancePolicyRules:getCompliancePolicyRules", args ?? new GetCompliancePolicyRulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compliance Policy Rules in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a list of Compliance policy rules in a compartment.
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
        ///     var testCompliancePolicyRules = Oci.FleetAppsManagement.GetCompliancePolicyRules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompliancePolicyId = testCompliancePolicy.Id,
        ///         DisplayName = compliancePolicyRuleDisplayName,
        ///         Id = compliancePolicyRuleId,
        ///         PatchName = testPatch.Name,
        ///         State = compliancePolicyRuleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCompliancePolicyRulesResult> Invoke(GetCompliancePolicyRulesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetCompliancePolicyRulesResult>("oci:FleetAppsManagement/getCompliancePolicyRules:getCompliancePolicyRules", args ?? new GetCompliancePolicyRulesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compliance Policy Rules in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a list of Compliance policy rules in a compartment.
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
        ///     var testCompliancePolicyRules = Oci.FleetAppsManagement.GetCompliancePolicyRules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompliancePolicyId = testCompliancePolicy.Id,
        ///         DisplayName = compliancePolicyRuleDisplayName,
        ///         Id = compliancePolicyRuleId,
        ///         PatchName = testPatch.Name,
        ///         State = compliancePolicyRuleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCompliancePolicyRulesResult> Invoke(GetCompliancePolicyRulesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetCompliancePolicyRulesResult>("oci:FleetAppsManagement/getCompliancePolicyRules:getCompliancePolicyRules", args ?? new GetCompliancePolicyRulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetCompliancePolicyRulesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// unique CompliancePolicy identifier.
        /// </summary>
        [Input("compliancePolicyId")]
        public string? CompliancePolicyId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetCompliancePolicyRulesFilterArgs>? _filters;
        public List<Inputs.GetCompliancePolicyRulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCompliancePolicyRulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources that match the patch selection against the given patch name.
        /// </summary>
        [Input("patchName")]
        public string? PatchName { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetCompliancePolicyRulesArgs()
        {
        }
        public static new GetCompliancePolicyRulesArgs Empty => new GetCompliancePolicyRulesArgs();
    }

    public sealed class GetCompliancePolicyRulesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// unique CompliancePolicy identifier.
        /// </summary>
        [Input("compliancePolicyId")]
        public Input<string>? CompliancePolicyId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetCompliancePolicyRulesFilterInputArgs>? _filters;
        public InputList<Inputs.GetCompliancePolicyRulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetCompliancePolicyRulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only resources that match the patch selection against the given patch name.
        /// </summary>
        [Input("patchName")]
        public Input<string>? PatchName { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetCompliancePolicyRulesInvokeArgs()
        {
        }
        public static new GetCompliancePolicyRulesInvokeArgs Empty => new GetCompliancePolicyRulesInvokeArgs();
    }


    [OutputType]
    public sealed class GetCompliancePolicyRulesResult
    {
        /// <summary>
        /// The OCID of the compartment the CompliancePolicyRule belongs to.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Unique OCID of the CompliancePolicy.
        /// </summary>
        public readonly string? CompliancePolicyId;
        /// <summary>
        /// The list of compliance_policy_rule_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCompliancePolicyRulesCompliancePolicyRuleCollectionResult> CompliancePolicyRuleCollections;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetCompliancePolicyRulesFilterResult> Filters;
        /// <summary>
        /// Unique OCID of the CompliancePolicyRule.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// Patch Name.
        /// </summary>
        public readonly string? PatchName;
        /// <summary>
        /// The current state of the CompliancePolicyRule.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetCompliancePolicyRulesResult(
            string? compartmentId,

            string? compliancePolicyId,

            ImmutableArray<Outputs.GetCompliancePolicyRulesCompliancePolicyRuleCollectionResult> compliancePolicyRuleCollections,

            string? displayName,

            ImmutableArray<Outputs.GetCompliancePolicyRulesFilterResult> filters,

            string? id,

            string? patchName,

            string? state)
        {
            CompartmentId = compartmentId;
            CompliancePolicyId = compliancePolicyId;
            CompliancePolicyRuleCollections = compliancePolicyRuleCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            PatchName = patchName;
            State = state;
        }
    }
}
