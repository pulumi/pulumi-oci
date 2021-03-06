// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseUserRoles
    {
        /// <summary>
        /// This data source provides the list of Managed Database User Roles in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of roles granted to a specific user.
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
        ///         var testManagedDatabaseUserRoles = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseUserRoles.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseUserRolesArgs
        ///         {
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             UserName = oci_identity_user.Test_user.Name,
        ///             Name = @var.Managed_database_user_role_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabaseUserRolesResult> InvokeAsync(GetManagedDatabaseUserRolesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseUserRolesResult>("oci:DatabaseManagement/getManagedDatabaseUserRoles:getManagedDatabaseUserRoles", args ?? new GetManagedDatabaseUserRolesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database User Roles in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of roles granted to a specific user.
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
        ///         var testManagedDatabaseUserRoles = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseUserRoles.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseUserRolesArgs
        ///         {
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             UserName = oci_identity_user.Test_user.Name,
        ///             Name = @var.Managed_database_user_role_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabaseUserRolesResult> Invoke(GetManagedDatabaseUserRolesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseUserRolesResult>("oci:DatabaseManagement/getManagedDatabaseUserRoles:getManagedDatabaseUserRoles", args ?? new GetManagedDatabaseUserRolesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseUserRolesArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseUserRolesFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseUserRolesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseUserRolesFilterArgs>());
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

        public GetManagedDatabaseUserRolesArgs()
        {
        }
    }

    public sealed class GetManagedDatabaseUserRolesInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseUserRolesFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseUserRolesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseUserRolesFilterInputArgs>());
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

        public GetManagedDatabaseUserRolesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagedDatabaseUserRolesResult
    {
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUserRolesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The name of the role granted to the user.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of role_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUserRolesRoleCollectionResult> RoleCollections;
        public readonly string UserName;

        [OutputConstructor]
        private GetManagedDatabaseUserRolesResult(
            ImmutableArray<Outputs.GetManagedDatabaseUserRolesFilterResult> filters,

            string id,

            string managedDatabaseId,

            string? name,

            ImmutableArray<Outputs.GetManagedDatabaseUserRolesRoleCollectionResult> roleCollections,

            string userName)
        {
            Filters = filters;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            RoleCollections = roleCollections;
            UserName = userName;
        }
    }
}
