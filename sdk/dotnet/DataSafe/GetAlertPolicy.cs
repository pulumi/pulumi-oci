// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetAlertPolicy
    {
        /// <summary>
        /// This data source provides details about a specific Alert Policy resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of alert policy by its ID.
        /// 
        /// ## Example Usage
        /// 
        /// &lt;!--Start PulumiCodeChooser --&gt;
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAlertPolicy = Oci.DataSafe.GetAlertPolicy.Invoke(new()
        ///     {
        ///         AlertPolicyId = oci_data_safe_alert_policy.Test_alert_policy.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// &lt;!--End PulumiCodeChooser --&gt;
        /// </summary>
        public static Task<GetAlertPolicyResult> InvokeAsync(GetAlertPolicyArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAlertPolicyResult>("oci:DataSafe/getAlertPolicy:getAlertPolicy", args ?? new GetAlertPolicyArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Alert Policy resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of alert policy by its ID.
        /// 
        /// ## Example Usage
        /// 
        /// &lt;!--Start PulumiCodeChooser --&gt;
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAlertPolicy = Oci.DataSafe.GetAlertPolicy.Invoke(new()
        ///     {
        ///         AlertPolicyId = oci_data_safe_alert_policy.Test_alert_policy.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// &lt;!--End PulumiCodeChooser --&gt;
        /// </summary>
        public static Output<GetAlertPolicyResult> Invoke(GetAlertPolicyInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAlertPolicyResult>("oci:DataSafe/getAlertPolicy:getAlertPolicy", args ?? new GetAlertPolicyInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAlertPolicyArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        [Input("alertPolicyId", required: true)]
        public string AlertPolicyId { get; set; } = null!;

        public GetAlertPolicyArgs()
        {
        }
        public static new GetAlertPolicyArgs Empty => new GetAlertPolicyArgs();
    }

    public sealed class GetAlertPolicyInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the alert policy.
        /// </summary>
        [Input("alertPolicyId", required: true)]
        public Input<string> AlertPolicyId { get; set; } = null!;

        public GetAlertPolicyInvokeArgs()
        {
        }
        public static new GetAlertPolicyInvokeArgs Empty => new GetAlertPolicyInvokeArgs();
    }


    [OutputType]
    public sealed class GetAlertPolicyResult
    {
        public readonly string AlertPolicyId;
        /// <summary>
        /// Indicates the Data Safe feature to which the alert policy belongs.
        /// </summary>
        public readonly string AlertPolicyType;
        /// <summary>
        /// The OCID of the compartment that contains the alert policy.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description of the alert policy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The display name of the alert policy.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates if the alert policy is user-defined (true) or pre-defined (false).
        /// </summary>
        public readonly bool IsUserDefined;
        /// <summary>
        /// Severity level of the alert raised by this policy.
        /// </summary>
        public readonly string Severity;
        /// <summary>
        /// The current state of the alert.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetAlertPolicyResult(
            string alertPolicyId,

            string alertPolicyType,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isUserDefined,

            string severity,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AlertPolicyId = alertPolicyId;
            AlertPolicyType = alertPolicyType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsUserDefined = isUserDefined;
            Severity = severity;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
