// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics
{
    public static class GetAnalyticsInstance
    {
        /// <summary>
        /// This data source provides details about a specific Analytics Instance resource in Oracle Cloud Infrastructure Analytics service.
        /// 
        /// Info for a specific Analytics instance.
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
        ///     var testAnalyticsInstance = Oci.Analytics.GetAnalyticsInstance.Invoke(new()
        ///     {
        ///         AnalyticsInstanceId = oci_analytics_analytics_instance.Test_analytics_instance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAnalyticsInstanceResult> InvokeAsync(GetAnalyticsInstanceArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAnalyticsInstanceResult>("oci:Analytics/getAnalyticsInstance:getAnalyticsInstance", args ?? new GetAnalyticsInstanceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Analytics Instance resource in Oracle Cloud Infrastructure Analytics service.
        /// 
        /// Info for a specific Analytics instance.
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
        ///     var testAnalyticsInstance = Oci.Analytics.GetAnalyticsInstance.Invoke(new()
        ///     {
        ///         AnalyticsInstanceId = oci_analytics_analytics_instance.Test_analytics_instance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAnalyticsInstanceResult> Invoke(GetAnalyticsInstanceInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAnalyticsInstanceResult>("oci:Analytics/getAnalyticsInstance:getAnalyticsInstance", args ?? new GetAnalyticsInstanceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAnalyticsInstanceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the AnalyticsInstance.
        /// </summary>
        [Input("analyticsInstanceId", required: true)]
        public string AnalyticsInstanceId { get; set; } = null!;

        public GetAnalyticsInstanceArgs()
        {
        }
        public static new GetAnalyticsInstanceArgs Empty => new GetAnalyticsInstanceArgs();
    }

    public sealed class GetAnalyticsInstanceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the AnalyticsInstance.
        /// </summary>
        [Input("analyticsInstanceId", required: true)]
        public Input<string> AnalyticsInstanceId { get; set; } = null!;

        public GetAnalyticsInstanceInvokeArgs()
        {
        }
        public static new GetAnalyticsInstanceInvokeArgs Empty => new GetAnalyticsInstanceInvokeArgs();
    }


    [OutputType]
    public sealed class GetAnalyticsInstanceResult
    {
        public readonly string AnalyticsInstanceId;
        /// <summary>
        /// Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAnalyticsInstanceCapacityResult> Capacities;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description of the vanity url.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Email address receiving notifications.
        /// </summary>
        public readonly string EmailNotification;
        /// <summary>
        /// Analytics feature set.
        /// </summary>
        public readonly string FeatureSet;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The Virtual Cloud Network OCID.
        /// </summary>
        public readonly string Id;
        public readonly string IdcsAccessToken;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The license used for the service.
        /// </summary>
        public readonly string LicenseType;
        /// <summary>
        /// The name of the Analytics instance. This name must be unique in the tenancy and cannot be changed.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAnalyticsInstanceNetworkEndpointDetailResult> NetworkEndpointDetails;
        /// <summary>
        /// URL of the Analytics service.
        /// </summary>
        public readonly string ServiceUrl;
        /// <summary>
        /// The current state of an instance.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetAnalyticsInstanceResult(
            string analyticsInstanceId,

            ImmutableArray<Outputs.GetAnalyticsInstanceCapacityResult> capacities,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string emailNotification,

            string featureSet,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string idcsAccessToken,

            string kmsKeyId,

            string licenseType,

            string name,

            ImmutableArray<Outputs.GetAnalyticsInstanceNetworkEndpointDetailResult> networkEndpointDetails,

            string serviceUrl,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            AnalyticsInstanceId = analyticsInstanceId;
            Capacities = capacities;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            EmailNotification = emailNotification;
            FeatureSet = featureSet;
            FreeformTags = freeformTags;
            Id = id;
            IdcsAccessToken = idcsAccessToken;
            KmsKeyId = kmsKeyId;
            LicenseType = licenseType;
            Name = name;
            NetworkEndpointDetails = networkEndpointDetails;
            ServiceUrl = serviceUrl;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}