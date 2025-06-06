// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetSecurityAssessmentFinding
    {
        public static Task<GetSecurityAssessmentFindingResult> InvokeAsync(GetSecurityAssessmentFindingArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSecurityAssessmentFindingResult>("oci:DataSafe/getSecurityAssessmentFinding:getSecurityAssessmentFinding", args ?? new GetSecurityAssessmentFindingArgs(), options.WithDefaults());

        public static Output<GetSecurityAssessmentFindingResult> Invoke(GetSecurityAssessmentFindingInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityAssessmentFindingResult>("oci:DataSafe/getSecurityAssessmentFinding:getSecurityAssessmentFinding", args ?? new GetSecurityAssessmentFindingInvokeArgs(), options.WithDefaults());

        public static Output<GetSecurityAssessmentFindingResult> Invoke(GetSecurityAssessmentFindingInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityAssessmentFindingResult>("oci:DataSafe/getSecurityAssessmentFinding:getSecurityAssessmentFinding", args ?? new GetSecurityAssessmentFindingInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSecurityAssessmentFindingArgs : global::Pulumi.InvokeArgs
    {
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("fields")]
        private List<string>? _fields;
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private List<Inputs.GetSecurityAssessmentFindingFilterArgs>? _filters;
        public List<Inputs.GetSecurityAssessmentFindingFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSecurityAssessmentFindingFilterArgs>());
            set => _filters = value;
        }

        [Input("findingKey")]
        public string? FindingKey { get; set; }

        [Input("isTopFinding")]
        public bool? IsTopFinding { get; set; }

        [Input("references")]
        public string? References { get; set; }

        [Input("scimQuery")]
        public string? ScimQuery { get; set; }

        [Input("securityAssessmentId", required: true)]
        public string SecurityAssessmentId { get; set; } = null!;

        [Input("severity")]
        public string? Severity { get; set; }

        [Input("state")]
        public string? State { get; set; }

        [Input("targetId")]
        public string? TargetId { get; set; }

        public GetSecurityAssessmentFindingArgs()
        {
        }
        public static new GetSecurityAssessmentFindingArgs Empty => new GetSecurityAssessmentFindingArgs();
    }

    public sealed class GetSecurityAssessmentFindingInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("fields")]
        private InputList<string>? _fields;
        public InputList<string> Fields
        {
            get => _fields ?? (_fields = new InputList<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetSecurityAssessmentFindingFilterInputArgs>? _filters;
        public InputList<Inputs.GetSecurityAssessmentFindingFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSecurityAssessmentFindingFilterInputArgs>());
            set => _filters = value;
        }

        [Input("findingKey")]
        public Input<string>? FindingKey { get; set; }

        [Input("isTopFinding")]
        public Input<bool>? IsTopFinding { get; set; }

        [Input("references")]
        public Input<string>? References { get; set; }

        [Input("scimQuery")]
        public Input<string>? ScimQuery { get; set; }

        [Input("securityAssessmentId", required: true)]
        public Input<string> SecurityAssessmentId { get; set; } = null!;

        [Input("severity")]
        public Input<string>? Severity { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        public GetSecurityAssessmentFindingInvokeArgs()
        {
        }
        public static new GetSecurityAssessmentFindingInvokeArgs Empty => new GetSecurityAssessmentFindingInvokeArgs();
    }


    [OutputType]
    public sealed class GetSecurityAssessmentFindingResult
    {
        public readonly string? AccessLevel;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<string> Fields;
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentFindingFilterResult> Filters;
        public readonly string? FindingKey;
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentFindingFindingResult> Findings;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsTopFinding;
        public readonly string? References;
        public readonly string? ScimQuery;
        public readonly string SecurityAssessmentId;
        public readonly string? Severity;
        public readonly string? State;
        public readonly string? TargetId;

        [OutputConstructor]
        private GetSecurityAssessmentFindingResult(
            string? accessLevel,

            bool? compartmentIdInSubtree,

            ImmutableArray<string> fields,

            ImmutableArray<Outputs.GetSecurityAssessmentFindingFilterResult> filters,

            string? findingKey,

            ImmutableArray<Outputs.GetSecurityAssessmentFindingFindingResult> findings,

            string id,

            bool? isTopFinding,

            string? references,

            string? scimQuery,

            string securityAssessmentId,

            string? severity,

            string? state,

            string? targetId)
        {
            AccessLevel = accessLevel;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Fields = fields;
            Filters = filters;
            FindingKey = findingKey;
            Findings = findings;
            Id = id;
            IsTopFinding = isTopFinding;
            References = references;
            ScimQuery = scimQuery;
            SecurityAssessmentId = securityAssessmentId;
            Severity = severity;
            State = state;
            TargetId = targetId;
        }
    }
}
