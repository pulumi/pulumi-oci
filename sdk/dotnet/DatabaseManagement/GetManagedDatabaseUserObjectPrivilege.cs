// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseUserObjectPrivilege
    {
        /// <summary>
        /// This data source provides details about a specific Managed Database User Object Privilege resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of object privileges granted to a specific user.
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
        ///     var testManagedDatabaseUserObjectPrivilege = Oci.DatabaseManagement.GetManagedDatabaseUserObjectPrivilege.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         UserName = testUser.Name,
        ///         Name = managedDatabaseUserObjectPrivilegeName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseUserObjectPrivilegeResult> InvokeAsync(GetManagedDatabaseUserObjectPrivilegeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseUserObjectPrivilegeResult>("oci:DatabaseManagement/getManagedDatabaseUserObjectPrivilege:getManagedDatabaseUserObjectPrivilege", args ?? new GetManagedDatabaseUserObjectPrivilegeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database User Object Privilege resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of object privileges granted to a specific user.
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
        ///     var testManagedDatabaseUserObjectPrivilege = Oci.DatabaseManagement.GetManagedDatabaseUserObjectPrivilege.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         UserName = testUser.Name,
        ///         Name = managedDatabaseUserObjectPrivilegeName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseUserObjectPrivilegeResult> Invoke(GetManagedDatabaseUserObjectPrivilegeInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseUserObjectPrivilegeResult>("oci:DatabaseManagement/getManagedDatabaseUserObjectPrivilege:getManagedDatabaseUserObjectPrivilege", args ?? new GetManagedDatabaseUserObjectPrivilegeInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database User Object Privilege resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of object privileges granted to a specific user.
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
        ///     var testManagedDatabaseUserObjectPrivilege = Oci.DatabaseManagement.GetManagedDatabaseUserObjectPrivilege.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         UserName = testUser.Name,
        ///         Name = managedDatabaseUserObjectPrivilegeName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseUserObjectPrivilegeResult> Invoke(GetManagedDatabaseUserObjectPrivilegeInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseUserObjectPrivilegeResult>("oci:DatabaseManagement/getManagedDatabaseUserObjectPrivilege:getManagedDatabaseUserObjectPrivilege", args ?? new GetManagedDatabaseUserObjectPrivilegeInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseUserObjectPrivilegeArgs : global::Pulumi.InvokeArgs
    {
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

        public GetManagedDatabaseUserObjectPrivilegeArgs()
        {
        }
        public static new GetManagedDatabaseUserObjectPrivilegeArgs Empty => new GetManagedDatabaseUserObjectPrivilegeArgs();
    }

    public sealed class GetManagedDatabaseUserObjectPrivilegeInvokeArgs : global::Pulumi.InvokeArgs
    {
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

        public GetManagedDatabaseUserObjectPrivilegeInvokeArgs()
        {
        }
        public static new GetManagedDatabaseUserObjectPrivilegeInvokeArgs Empty => new GetManagedDatabaseUserObjectPrivilegeInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseUserObjectPrivilegeResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An array of object privileges.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseUserObjectPrivilegeItemResult> Items;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The name of the privilege on the object.
        /// </summary>
        public readonly string? Name;
        public readonly string UserName;

        [OutputConstructor]
        private GetManagedDatabaseUserObjectPrivilegeResult(
            string id,

            ImmutableArray<Outputs.GetManagedDatabaseUserObjectPrivilegeItemResult> items,

            string managedDatabaseId,

            string? name,

            string userName)
        {
            Id = id;
            Items = items;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            UserName = userName;
        }
    }
}
