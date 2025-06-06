// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Identity Providers in Oracle Cloud Infrastructure Identity service.
//
// **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).
//
// Lists all the identity providers in your tenancy. You must specify the identity provider type (e.g., `SAML2` for
// identity providers using the SAML2.0 protocol). You must specify your tenancy's OCID as the value for the
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
//			_, err := identity.GetIdentityProviders(ctx, &identity.GetIdentityProvidersArgs{
//				CompartmentId: tenancyOcid,
//				Protocol:      identityProviderProtocol,
//				Name:          pulumi.StringRef(identityProviderName),
//				State:         pulumi.StringRef(identityProviderState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetIdentityProviders(ctx *pulumi.Context, args *GetIdentityProvidersArgs, opts ...pulumi.InvokeOption) (*GetIdentityProvidersResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetIdentityProvidersResult
	err := ctx.Invoke("oci:Identity/getIdentityProviders:getIdentityProviders", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIdentityProviders.
type GetIdentityProvidersArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                       `pulumi:"compartmentId"`
	Filters       []GetIdentityProvidersFilter `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// The protocol used for federation.
	Protocol string `pulumi:"protocol"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getIdentityProviders.
type GetIdentityProvidersResult struct {
	// The OCID of the tenancy containing the `IdentityProvider`.
	CompartmentId string                       `pulumi:"compartmentId"`
	Filters       []GetIdentityProvidersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of identity_providers.
	IdentityProviders []GetIdentityProvidersIdentityProvider `pulumi:"identityProviders"`
	// The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed. This is the name federated users see when choosing which identity provider to use when signing in to the Oracle Cloud Infrastructure Console.
	Name *string `pulumi:"name"`
	// The protocol used for federation. Allowed value: `SAML2`.  Example: `SAML2`
	Protocol string `pulumi:"protocol"`
	// The current state.
	State *string `pulumi:"state"`
}

func GetIdentityProvidersOutput(ctx *pulumi.Context, args GetIdentityProvidersOutputArgs, opts ...pulumi.InvokeOption) GetIdentityProvidersResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetIdentityProvidersResultOutput, error) {
			args := v.(GetIdentityProvidersArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getIdentityProviders:getIdentityProviders", args, GetIdentityProvidersResultOutput{}, options).(GetIdentityProvidersResultOutput), nil
		}).(GetIdentityProvidersResultOutput)
}

// A collection of arguments for invoking getIdentityProviders.
type GetIdentityProvidersOutputArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput                   `pulumi:"compartmentId"`
	Filters       GetIdentityProvidersFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The protocol used for federation.
	Protocol pulumi.StringInput `pulumi:"protocol"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetIdentityProvidersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIdentityProvidersArgs)(nil)).Elem()
}

// A collection of values returned by getIdentityProviders.
type GetIdentityProvidersResultOutput struct{ *pulumi.OutputState }

func (GetIdentityProvidersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIdentityProvidersResult)(nil)).Elem()
}

func (o GetIdentityProvidersResultOutput) ToGetIdentityProvidersResultOutput() GetIdentityProvidersResultOutput {
	return o
}

func (o GetIdentityProvidersResultOutput) ToGetIdentityProvidersResultOutputWithContext(ctx context.Context) GetIdentityProvidersResultOutput {
	return o
}

// The OCID of the tenancy containing the `IdentityProvider`.
func (o GetIdentityProvidersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetIdentityProvidersResultOutput) Filters() GetIdentityProvidersFilterArrayOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) []GetIdentityProvidersFilter { return v.Filters }).(GetIdentityProvidersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetIdentityProvidersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of identity_providers.
func (o GetIdentityProvidersResultOutput) IdentityProviders() GetIdentityProvidersIdentityProviderArrayOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) []GetIdentityProvidersIdentityProvider { return v.IdentityProviders }).(GetIdentityProvidersIdentityProviderArrayOutput)
}

// The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed. This is the name federated users see when choosing which identity provider to use when signing in to the Oracle Cloud Infrastructure Console.
func (o GetIdentityProvidersResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The protocol used for federation. Allowed value: `SAML2`.  Example: `SAML2`
func (o GetIdentityProvidersResultOutput) Protocol() pulumi.StringOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) string { return v.Protocol }).(pulumi.StringOutput)
}

// The current state.
func (o GetIdentityProvidersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIdentityProvidersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetIdentityProvidersResultOutput{})
}
