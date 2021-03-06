// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseUsers
    {
        /// <summary>
        /// This data source provides the list of Managed Database Users in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of users for the specified managedDatabaseId.
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
        ///         var testManagedDatabaseUsers = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseUsers.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseUsersArgs
        ///         {
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             Name = @var.Managed_database_user_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabaseUsersResult> InvokeAsync(GetManagedDatabaseUsersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseUsersResult>("oci:DatabaseManagement/getManagedDatabaseUsers:getManagedDatabaseUsers", args ?? new GetManagedDatabaseUsersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Users in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of users for the specified managedDatabaseId.
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
        ///         var testManagedDatabaseUsers = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseUsers.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseUsersArgs
        ///         {
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             Name = @var.Managed_database_user_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabaseUsersResult> Invoke(GetManagedDatabaseUsersInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseUsersResult>("oci:DatabaseManagement/getManagedDatabaseUsers:getManagedDatabaseUsers", args ?? new GetManagedDatabaseUsersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseUsersArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseUsersFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseUsersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseUsersFilterArgs>());
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

        public GetManagedDatabaseUsersArgs()
        {
        }
    }

    public sealed class GetManagedDatabaseUsersInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseUsersFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseUsersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseUsersFilterInputArgs>());
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

        public GetManagedDatabaseUsersInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagedDatabaseUsersResult
    {
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUsersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The name of the User.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of user_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUsersUserCollectionResult> UserCollections;

        [OutputConstructor]
        private GetManagedDatabaseUsersResult(
            ImmutableArray<Outputs.GetManagedDatabaseUsersFilterResult> filters,

            string id,

            string managedDatabaseId,

            string? name,

            ImmutableArray<Outputs.GetManagedDatabaseUsersUserCollectionResult> userCollections)
        {
            Filters = filters;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            UserCollections = userCollections;
        }
    }
}
