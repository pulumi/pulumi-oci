// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomain
    {
        /// <summary>
        /// This data source provides details about a specific Domain resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Get the specified domain's information.
        /// 
        /// - If the domain doesn't exists, returns 404 NOT FOUND.
        /// - If any internal error occurs, returns 500 INTERNAL SERVER ERROR.
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
        ///     var testDomain = Oci.Identity.GetDomain.Invoke(new()
        ///     {
        ///         DomainId = oci_identity_domain.Test_domain.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDomainResult> InvokeAsync(GetDomainArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDomainResult>("oci:Identity/getDomain:getDomain", args ?? new GetDomainArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Domain resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Get the specified domain's information.
        /// 
        /// - If the domain doesn't exists, returns 404 NOT FOUND.
        /// - If any internal error occurs, returns 500 INTERNAL SERVER ERROR.
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
        ///     var testDomain = Oci.Identity.GetDomain.Invoke(new()
        ///     {
        ///         DomainId = oci_identity_domain.Test_domain.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDomainResult> Invoke(GetDomainInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDomainResult>("oci:Identity/getDomain:getDomain", args ?? new GetDomainInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the domain
        /// </summary>
        [Input("domainId", required: true)]
        public string DomainId { get; set; } = null!;

        public GetDomainArgs()
        {
        }
        public static new GetDomainArgs Empty => new GetDomainArgs();
    }

    public sealed class GetDomainInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the domain
        /// </summary>
        [Input("domainId", required: true)]
        public Input<string> DomainId { get; set; } = null!;

        public GetDomainInvokeArgs()
        {
        }
        public static new GetDomainInvokeArgs Empty => new GetDomainInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainResult
    {
        public readonly string AdminEmail;
        public readonly string AdminFirstName;
        public readonly string AdminLastName;
        public readonly string AdminUserName;
        /// <summary>
        /// The OCID of the compartment containing the domain.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The domain descripition
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The mutable display name of the domain
        /// </summary>
        public readonly string DisplayName;
        public readonly string DomainId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The home region for the domain. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.  Example: `us-phoenix-1`
        /// </summary>
        public readonly string HomeRegion;
        /// <summary>
        /// Region specific domain URL.
        /// </summary>
        public readonly string HomeRegionUrl;
        /// <summary>
        /// The OCID of the domain
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether domain is hidden on login screen or not.
        /// </summary>
        public readonly bool IsHiddenOnLogin;
        public readonly bool IsNotificationBypassed;
        public readonly bool IsPrimaryEmailRequired;
        /// <summary>
        /// The License type of Domain
        /// </summary>
        public readonly string LicenseType;
        /// <summary>
        /// Any additional details about the current state of the Domain.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The regions domain is replication to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainReplicaRegionResult> ReplicaRegions;
        /// <summary>
        /// The current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Date and time the domain was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The type of the domain.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Region agnostic domain URL.
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetDomainResult(
            string adminEmail,

            string adminFirstName,

            string adminLastName,

            string adminUserName,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string domainId,

            ImmutableDictionary<string, object> freeformTags,

            string homeRegion,

            string homeRegionUrl,

            string id,

            bool isHiddenOnLogin,

            bool isNotificationBypassed,

            bool isPrimaryEmailRequired,

            string licenseType,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetDomainReplicaRegionResult> replicaRegions,

            string state,

            string timeCreated,

            string type,

            string url)
        {
            AdminEmail = adminEmail;
            AdminFirstName = adminFirstName;
            AdminLastName = adminLastName;
            AdminUserName = adminUserName;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            DomainId = domainId;
            FreeformTags = freeformTags;
            HomeRegion = homeRegion;
            HomeRegionUrl = homeRegionUrl;
            Id = id;
            IsHiddenOnLogin = isHiddenOnLogin;
            IsNotificationBypassed = isNotificationBypassed;
            IsPrimaryEmailRequired = isPrimaryEmailRequired;
            LicenseType = licenseType;
            LifecycleDetails = lifecycleDetails;
            ReplicaRegions = replicaRegions;
            State = state;
            TimeCreated = timeCreated;
            Type = type;
            Url = url;
        }
    }
}