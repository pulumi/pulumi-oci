// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseUserProxiedForUsers
    {
        /// <summary>
        /// This data source provides the list of Managed Database User Proxied For Users in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of users on whose behalf the current user acts as proxy.
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
        ///     var testManagedDatabaseUserProxiedForUsers = Oci.DatabaseManagement.GetManagedDatabaseUserProxiedForUsers.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         UserName = oci_identity_user.Test_user.Name,
        ///         Name = @var.Managed_database_user_proxied_for_user_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabaseUserProxiedForUsersResult> InvokeAsync(GetManagedDatabaseUserProxiedForUsersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseUserProxiedForUsersResult>("oci:DatabaseManagement/getManagedDatabaseUserProxiedForUsers:getManagedDatabaseUserProxiedForUsers", args ?? new GetManagedDatabaseUserProxiedForUsersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database User Proxied For Users in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of users on whose behalf the current user acts as proxy.
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
        ///     var testManagedDatabaseUserProxiedForUsers = Oci.DatabaseManagement.GetManagedDatabaseUserProxiedForUsers.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         UserName = oci_identity_user.Test_user.Name,
        ///         Name = @var.Managed_database_user_proxied_for_user_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabaseUserProxiedForUsersResult> Invoke(GetManagedDatabaseUserProxiedForUsersInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseUserProxiedForUsersResult>("oci:DatabaseManagement/getManagedDatabaseUserProxiedForUsers:getManagedDatabaseUserProxiedForUsers", args ?? new GetManagedDatabaseUserProxiedForUsersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseUserProxiedForUsersArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseUserProxiedForUsersFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseUserProxiedForUsersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseUserProxiedForUsersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The name of the user whose details are to be viewed.
        /// </summary>
        [Input("userName", required: true)]
        public string UserName { get; set; } = null!;

        public GetManagedDatabaseUserProxiedForUsersArgs()
        {
        }
        public static new GetManagedDatabaseUserProxiedForUsersArgs Empty => new GetManagedDatabaseUserProxiedForUsersArgs();
    }

    public sealed class GetManagedDatabaseUserProxiedForUsersInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseUserProxiedForUsersFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseUserProxiedForUsersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseUserProxiedForUsersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The name of the user whose details are to be viewed.
        /// </summary>
        [Input("userName", required: true)]
        public Input<string> UserName { get; set; } = null!;

        public GetManagedDatabaseUserProxiedForUsersInvokeArgs()
        {
        }
        public static new GetManagedDatabaseUserProxiedForUsersInvokeArgs Empty => new GetManagedDatabaseUserProxiedForUsersInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseUserProxiedForUsersResult
    {
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUserProxiedForUsersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The name of a proxy user or the name of the client user.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of proxied_for_user_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUserProxiedForUsersProxiedForUserCollectionResult> ProxiedForUserCollections;
        public readonly string UserName;

        [OutputConstructor]
        private GetManagedDatabaseUserProxiedForUsersResult(
            ImmutableArray<Outputs.GetManagedDatabaseUserProxiedForUsersFilterResult> filters,

            string id,

            string managedDatabaseId,

            string? name,

            ImmutableArray<Outputs.GetManagedDatabaseUserProxiedForUsersProxiedForUserCollectionResult> proxiedForUserCollections,

            string userName)
        {
            Filters = filters;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            ProxiedForUserCollections = proxiedForUserCollections;
            UserName = userName;
        }
    }
}