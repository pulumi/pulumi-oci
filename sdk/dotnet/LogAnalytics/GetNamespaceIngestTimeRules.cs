// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetNamespaceIngestTimeRules
    {
        /// <summary>
        /// This data source provides the list of Namespace Ingest Time Rules in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of ingest time rules in a compartment. You may limit the number of rules, provide sorting options, and filter the results.
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
        ///     var testNamespaceIngestTimeRules = Oci.LogAnalytics.GetNamespaceIngestTimeRules.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         Namespace = @var.Namespace_ingest_time_rule_namespace,
        ///         ConditionKind = @var.Namespace_ingest_time_rule_condition_kind,
        ///         DisplayName = @var.Namespace_ingest_time_rule_display_name,
        ///         FieldName = @var.Namespace_ingest_time_rule_field_name,
        ///         FieldValue = @var.Namespace_ingest_time_rule_field_value,
        ///         State = @var.Namespace_ingest_time_rule_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetNamespaceIngestTimeRulesResult> InvokeAsync(GetNamespaceIngestTimeRulesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNamespaceIngestTimeRulesResult>("oci:LogAnalytics/getNamespaceIngestTimeRules:getNamespaceIngestTimeRules", args ?? new GetNamespaceIngestTimeRulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Ingest Time Rules in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of ingest time rules in a compartment. You may limit the number of rules, provide sorting options, and filter the results.
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
        ///     var testNamespaceIngestTimeRules = Oci.LogAnalytics.GetNamespaceIngestTimeRules.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         Namespace = @var.Namespace_ingest_time_rule_namespace,
        ///         ConditionKind = @var.Namespace_ingest_time_rule_condition_kind,
        ///         DisplayName = @var.Namespace_ingest_time_rule_display_name,
        ///         FieldName = @var.Namespace_ingest_time_rule_field_name,
        ///         FieldValue = @var.Namespace_ingest_time_rule_field_value,
        ///         State = @var.Namespace_ingest_time_rule_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetNamespaceIngestTimeRulesResult> Invoke(GetNamespaceIngestTimeRulesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceIngestTimeRulesResult>("oci:LogAnalytics/getNamespaceIngestTimeRules:getNamespaceIngestTimeRules", args ?? new GetNamespaceIngestTimeRulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNamespaceIngestTimeRulesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The ingest time rule condition kind used for filtering. Only rules with conditions of the specified kind will be returned.
        /// </summary>
        [Input("conditionKind")]
        public string? ConditionKind { get; set; }

        /// <summary>
        /// A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The field name used for filtering. Only rules using the specified field name will be returned.
        /// </summary>
        [Input("fieldName")]
        public string? FieldName { get; set; }

        /// <summary>
        /// The field value used for filtering. Only rules using the specified field value will be returned.
        /// </summary>
        [Input("fieldValue")]
        public string? FieldValue { get; set; }

        [Input("filters")]
        private List<Inputs.GetNamespaceIngestTimeRulesFilterArgs>? _filters;
        public List<Inputs.GetNamespaceIngestTimeRulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNamespaceIngestTimeRulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetNamespaceIngestTimeRulesArgs()
        {
        }
        public static new GetNamespaceIngestTimeRulesArgs Empty => new GetNamespaceIngestTimeRulesArgs();
    }

    public sealed class GetNamespaceIngestTimeRulesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The ingest time rule condition kind used for filtering. Only rules with conditions of the specified kind will be returned.
        /// </summary>
        [Input("conditionKind")]
        public Input<string>? ConditionKind { get; set; }

        /// <summary>
        /// A filter to return rules whose displayName matches in whole or in part the specified value. The match is case-insensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The field name used for filtering. Only rules using the specified field name will be returned.
        /// </summary>
        [Input("fieldName")]
        public Input<string>? FieldName { get; set; }

        /// <summary>
        /// The field value used for filtering. Only rules using the specified field value will be returned.
        /// </summary>
        [Input("fieldValue")]
        public Input<string>? FieldValue { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetNamespaceIngestTimeRulesFilterInputArgs>? _filters;
        public InputList<Inputs.GetNamespaceIngestTimeRulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNamespaceIngestTimeRulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The rule lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetNamespaceIngestTimeRulesInvokeArgs()
        {
        }
        public static new GetNamespaceIngestTimeRulesInvokeArgs Empty => new GetNamespaceIngestTimeRulesInvokeArgs();
    }


    [OutputType]
    public sealed class GetNamespaceIngestTimeRulesResult
    {
        /// <summary>
        /// Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        public readonly string? ConditionKind;
        /// <summary>
        /// The ingest time rule display name.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The field name to be evaluated.
        /// </summary>
        public readonly string? FieldName;
        /// <summary>
        /// The field value to be evaluated.
        /// </summary>
        public readonly string? FieldValue;
        public readonly ImmutableArray<Outputs.GetNamespaceIngestTimeRulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of ingest_time_rule_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionResult> IngestTimeRuleSummaryCollections;
        /// <summary>
        /// The namespace of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters and underscores (_).
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The current state of the ingest time rule.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetNamespaceIngestTimeRulesResult(
            string compartmentId,

            string? conditionKind,

            string? displayName,

            string? fieldName,

            string? fieldValue,

            ImmutableArray<Outputs.GetNamespaceIngestTimeRulesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetNamespaceIngestTimeRulesIngestTimeRuleSummaryCollectionResult> ingestTimeRuleSummaryCollections,

            string @namespace,

            string? state)
        {
            CompartmentId = compartmentId;
            ConditionKind = conditionKind;
            DisplayName = displayName;
            FieldName = fieldName;
            FieldValue = fieldValue;
            Filters = filters;
            Id = id;
            IngestTimeRuleSummaryCollections = ingestTimeRuleSummaryCollections;
            Namespace = @namespace;
            State = state;
        }
    }
}