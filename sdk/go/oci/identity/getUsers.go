// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Users in Oracle Cloud Infrastructure Identity service.
//
// Lists the users in your tenancy. You must specify your tenancy's OCID as the value for the
// compartment ID (remember that the tenancy is simply the root compartment).
// See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.GetUsers(ctx, &identity.GetUsersArgs{
//				CompartmentId:      tenancyOcid,
//				ExternalIdentifier: pulumi.StringRef(userExternalIdentifier),
//				IdentityProviderId: pulumi.StringRef(testIdentityProvider.Id),
//				Name:               pulumi.StringRef(userName),
//				State:              pulumi.StringRef(userState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetUsers(ctx *pulumi.Context, args *GetUsersArgs, opts ...pulumi.InvokeOption) (*GetUsersResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetUsersResult
	err := ctx.Invoke("oci:Identity/getUsers:getUsers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getUsers.
type GetUsersArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string `pulumi:"compartmentId"`
	// The id of a user in the identity provider.
	ExternalIdentifier *string          `pulumi:"externalIdentifier"`
	Filters            []GetUsersFilter `pulumi:"filters"`
	// The id of the identity provider.
	IdentityProviderId *string `pulumi:"identityProviderId"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getUsers.
type GetUsersResult struct {
	// The OCID of the tenancy containing the user.
	CompartmentId string `pulumi:"compartmentId"`
	// Identifier of the user in the identity provider
	ExternalIdentifier *string          `pulumi:"externalIdentifier"`
	Filters            []GetUsersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the `IdentityProvider` this user belongs to.
	IdentityProviderId *string `pulumi:"identityProviderId"`
	// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
	// The user's current state.
	State *string `pulumi:"state"`
	// The list of users.
	Users []GetUsersUser `pulumi:"users"`
}

func GetUsersOutput(ctx *pulumi.Context, args GetUsersOutputArgs, opts ...pulumi.InvokeOption) GetUsersResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetUsersResultOutput, error) {
			args := v.(GetUsersArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getUsers:getUsers", args, GetUsersResultOutput{}, options).(GetUsersResultOutput), nil
		}).(GetUsersResultOutput)
}

// A collection of arguments for invoking getUsers.
type GetUsersOutputArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The id of a user in the identity provider.
	ExternalIdentifier pulumi.StringPtrInput    `pulumi:"externalIdentifier"`
	Filters            GetUsersFilterArrayInput `pulumi:"filters"`
	// The id of the identity provider.
	IdentityProviderId pulumi.StringPtrInput `pulumi:"identityProviderId"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetUsersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUsersArgs)(nil)).Elem()
}

// A collection of values returned by getUsers.
type GetUsersResultOutput struct{ *pulumi.OutputState }

func (GetUsersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetUsersResult)(nil)).Elem()
}

func (o GetUsersResultOutput) ToGetUsersResultOutput() GetUsersResultOutput {
	return o
}

func (o GetUsersResultOutput) ToGetUsersResultOutputWithContext(ctx context.Context) GetUsersResultOutput {
	return o
}

// The OCID of the tenancy containing the user.
func (o GetUsersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetUsersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Identifier of the user in the identity provider
func (o GetUsersResultOutput) ExternalIdentifier() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUsersResult) *string { return v.ExternalIdentifier }).(pulumi.StringPtrOutput)
}

func (o GetUsersResultOutput) Filters() GetUsersFilterArrayOutput {
	return o.ApplyT(func(v GetUsersResult) []GetUsersFilter { return v.Filters }).(GetUsersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetUsersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetUsersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the `IdentityProvider` this user belongs to.
func (o GetUsersResultOutput) IdentityProviderId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUsersResult) *string { return v.IdentityProviderId }).(pulumi.StringPtrOutput)
}

// The name you assign to the user during creation. This is the user's login for the Console. The name must be unique across all users in the tenancy and cannot be changed.
func (o GetUsersResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUsersResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The user's current state.
func (o GetUsersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetUsersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of users.
func (o GetUsersResultOutput) Users() GetUsersUserArrayOutput {
	return o.ApplyT(func(v GetUsersResult) []GetUsersUser { return v.Users }).(GetUsersUserArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetUsersResultOutput{})
}
