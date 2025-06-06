// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Zpr
{
    public static class GetConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Zpr service.
        /// 
        /// Retrieves the ZPR configuration details for the root compartment (the root compartment is the tenancy).
        /// Returns ZPR configuration for root compartment (the root compartment is the tenancy).
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
        ///     var testConfiguration = Oci.Zpr.GetConfiguration.Invoke(new()
        ///     {
        ///         CompartmentId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetConfigurationResult> InvokeAsync(GetConfigurationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetConfigurationResult>("oci:Zpr/getConfiguration:getConfiguration", args ?? new GetConfigurationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Zpr service.
        /// 
        /// Retrieves the ZPR configuration details for the root compartment (the root compartment is the tenancy).
        /// Returns ZPR configuration for root compartment (the root compartment is the tenancy).
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
        ///     var testConfiguration = Oci.Zpr.GetConfiguration.Invoke(new()
        ///     {
        ///         CompartmentId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetConfigurationResult> Invoke(GetConfigurationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetConfigurationResult>("oci:Zpr/getConfiguration:getConfiguration", args ?? new GetConfigurationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Zpr service.
        /// 
        /// Retrieves the ZPR configuration details for the root compartment (the root compartment is the tenancy).
        /// Returns ZPR configuration for root compartment (the root compartment is the tenancy).
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
        ///     var testConfiguration = Oci.Zpr.GetConfiguration.Invoke(new()
        ///     {
        ///         CompartmentId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetConfigurationResult> Invoke(GetConfigurationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetConfigurationResult>("oci:Zpr/getConfiguration:getConfiguration", args ?? new GetConfigurationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetConfigurationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        public GetConfigurationArgs()
        {
        }
        public static new GetConfigurationArgs Empty => new GetConfigurationArgs();
    }

    public sealed class GetConfigurationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        public GetConfigurationInvokeArgs()
        {
        }
        public static new GetConfigurationInvokeArgs Empty => new GetConfigurationInvokeArgs();
    }


    [OutputType]
    public sealed class GetConfigurationResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy into which ZPR will be onboarded.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ZprConfiguration.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message that describes the current state of ZPR in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of ZPR in the tenancy.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time that ZPR was onboarded to the tenancy, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time that ZPR was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The enabled or disabled status of ZPR in tenancy.
        /// </summary>
        public readonly string ZprStatus;

        [OutputConstructor]
        private GetConfigurationResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string zprStatus)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            ZprStatus = zprStatus;
        }
    }
}
