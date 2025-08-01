// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement
{
    public static class GetFleetCredential
    {
        /// <summary>
        /// This data source provides details about a specific Fleet Credential resource in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a fleet credential by identifier.
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
        ///     var testFleetCredential = Oci.FleetAppsManagement.GetFleetCredential.Invoke(new()
        ///     {
        ///         FleetCredentialId = testFleetCredentialOciFleetAppsManagementFleetCredential.Id,
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFleetCredentialResult> InvokeAsync(GetFleetCredentialArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFleetCredentialResult>("oci:FleetAppsManagement/getFleetCredential:getFleetCredential", args ?? new GetFleetCredentialArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fleet Credential resource in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a fleet credential by identifier.
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
        ///     var testFleetCredential = Oci.FleetAppsManagement.GetFleetCredential.Invoke(new()
        ///     {
        ///         FleetCredentialId = testFleetCredentialOciFleetAppsManagementFleetCredential.Id,
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFleetCredentialResult> Invoke(GetFleetCredentialInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFleetCredentialResult>("oci:FleetAppsManagement/getFleetCredential:getFleetCredential", args ?? new GetFleetCredentialInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fleet Credential resource in Oracle Cloud Infrastructure Fleet Apps Management service.
        /// 
        /// Gets a fleet credential by identifier.
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
        ///     var testFleetCredential = Oci.FleetAppsManagement.GetFleetCredential.Invoke(new()
        ///     {
        ///         FleetCredentialId = testFleetCredentialOciFleetAppsManagementFleetCredential.Id,
        ///         FleetId = testFleet.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFleetCredentialResult> Invoke(GetFleetCredentialInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFleetCredentialResult>("oci:FleetAppsManagement/getFleetCredential:getFleetCredential", args ?? new GetFleetCredentialInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFleetCredentialArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FleetCredential identifier
        /// </summary>
        [Input("fleetCredentialId", required: true)]
        public string FleetCredentialId { get; set; } = null!;

        /// <summary>
        /// Unique Fleet identifier.
        /// </summary>
        [Input("fleetId", required: true)]
        public string FleetId { get; set; } = null!;

        public GetFleetCredentialArgs()
        {
        }
        public static new GetFleetCredentialArgs Empty => new GetFleetCredentialArgs();
    }

    public sealed class GetFleetCredentialInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FleetCredential identifier
        /// </summary>
        [Input("fleetCredentialId", required: true)]
        public Input<string> FleetCredentialId { get; set; } = null!;

        /// <summary>
        /// Unique Fleet identifier.
        /// </summary>
        [Input("fleetId", required: true)]
        public Input<string> FleetId { get; set; } = null!;

        public GetFleetCredentialInvokeArgs()
        {
        }
        public static new GetFleetCredentialInvokeArgs Empty => new GetFleetCredentialInvokeArgs();
    }


    [OutputType]
    public sealed class GetFleetCredentialResult
    {
        /// <summary>
        /// Compartment OCID
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Credential specific Details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetCredentialEntitySpecificResult> EntitySpecifics;
        public readonly string FleetCredentialId;
        public readonly string FleetId;
        /// <summary>
        /// The unique id of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Credential Details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetCredentialPasswordResult> Passwords;
        /// <summary>
        /// The current state of the FleetCredential.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Credential Details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetCredentialUserResult> Users;

        [OutputConstructor]
        private GetFleetCredentialResult(
            string compartmentId,

            string displayName,

            ImmutableArray<Outputs.GetFleetCredentialEntitySpecificResult> entitySpecifics,

            string fleetCredentialId,

            string fleetId,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetFleetCredentialPasswordResult> passwords,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            ImmutableArray<Outputs.GetFleetCredentialUserResult> users)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            EntitySpecifics = entitySpecifics;
            FleetCredentialId = fleetCredentialId;
            FleetId = fleetId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Passwords = passwords;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Users = users;
        }
    }
}
