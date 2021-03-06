// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetDataMaskRules
    {
        /// <summary>
        /// This data source provides the list of Data Mask Rules in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of all Data Mask Rules in the root 'compartmentId' passed.
        /// 
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
        ///         var testDataMaskRules = Output.Create(Oci.CloudGuard.GetDataMaskRules.InvokeAsync(new Oci.CloudGuard.GetDataMaskRulesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Data_mask_rule_access_level,
        ///             DataMaskRuleStatus = @var.Data_mask_rule_data_mask_rule_status,
        ///             DisplayName = @var.Data_mask_rule_display_name,
        ///             IamGroupId = oci_identity_group.Test_group.Id,
        ///             State = @var.Data_mask_rule_state,
        ///             TargetId = oci_cloud_guard_target.Test_target.Id,
        ///             TargetType = @var.Data_mask_rule_target_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataMaskRulesResult> InvokeAsync(GetDataMaskRulesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDataMaskRulesResult>("oci:CloudGuard/getDataMaskRules:getDataMaskRules", args ?? new GetDataMaskRulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Data Mask Rules in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of all Data Mask Rules in the root 'compartmentId' passed.
        /// 
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
        ///         var testDataMaskRules = Output.Create(Oci.CloudGuard.GetDataMaskRules.InvokeAsync(new Oci.CloudGuard.GetDataMaskRulesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Data_mask_rule_access_level,
        ///             DataMaskRuleStatus = @var.Data_mask_rule_data_mask_rule_status,
        ///             DisplayName = @var.Data_mask_rule_display_name,
        ///             IamGroupId = oci_identity_group.Test_group.Id,
        ///             State = @var.Data_mask_rule_state,
        ///             TargetId = oci_cloud_guard_target.Test_target.Id,
        ///             TargetType = @var.Data_mask_rule_target_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDataMaskRulesResult> Invoke(GetDataMaskRulesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDataMaskRulesResult>("oci:CloudGuard/getDataMaskRules:getDataMaskRules", args ?? new GetDataMaskRulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDataMaskRulesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The status of the dataMaskRule.
        /// </summary>
        [Input("dataMaskRuleStatus")]
        public string? DataMaskRuleStatus { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDataMaskRulesFilterArgs>? _filters;
        public List<Inputs.GetDataMaskRulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataMaskRulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// OCID of iamGroup
        /// </summary>
        [Input("iamGroupId")]
        public string? IamGroupId { get; set; }

        /// <summary>
        /// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// OCID of target
        /// </summary>
        [Input("targetId")]
        public string? TargetId { get; set; }

        /// <summary>
        /// Type of target
        /// </summary>
        [Input("targetType")]
        public string? TargetType { get; set; }

        public GetDataMaskRulesArgs()
        {
        }
    }

    public sealed class GetDataMaskRulesInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The status of the dataMaskRule.
        /// </summary>
        [Input("dataMaskRuleStatus")]
        public Input<string>? DataMaskRuleStatus { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDataMaskRulesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDataMaskRulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDataMaskRulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// OCID of iamGroup
        /// </summary>
        [Input("iamGroupId")]
        public Input<string>? IamGroupId { get; set; }

        /// <summary>
        /// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// OCID of target
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// Type of target
        /// </summary>
        [Input("targetType")]
        public Input<string>? TargetType { get; set; }

        public GetDataMaskRulesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDataMaskRulesResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// Compartment Identifier where the resource is created
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of data_mask_rule_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataMaskRulesDataMaskRuleCollectionResult> DataMaskRuleCollections;
        /// <summary>
        /// The status of the dataMaskRule.
        /// </summary>
        public readonly string? DataMaskRuleStatus;
        /// <summary>
        /// Data Mask Rule Identifier, can be renamed
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDataMaskRulesFilterResult> Filters;
        /// <summary>
        /// IAM Group id associated with the data mask rule
        /// </summary>
        public readonly string? IamGroupId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the DataMaskRule.
        /// </summary>
        public readonly string? State;
        public readonly string? TargetId;
        public readonly string? TargetType;

        [OutputConstructor]
        private GetDataMaskRulesResult(
            string? accessLevel,

            string compartmentId,

            ImmutableArray<Outputs.GetDataMaskRulesDataMaskRuleCollectionResult> dataMaskRuleCollections,

            string? dataMaskRuleStatus,

            string? displayName,

            ImmutableArray<Outputs.GetDataMaskRulesFilterResult> filters,

            string? iamGroupId,

            string id,

            string? state,

            string? targetId,

            string? targetType)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            DataMaskRuleCollections = dataMaskRuleCollections;
            DataMaskRuleStatus = dataMaskRuleStatus;
            DisplayName = displayName;
            Filters = filters;
            IamGroupId = iamGroupId;
            Id = id;
            State = state;
            TargetId = targetId;
            TargetType = targetType;
        }
    }
}
