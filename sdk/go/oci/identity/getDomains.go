// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Domains in Oracle Cloud Infrastructure Identity service.
//
// List all domains that are homed or have a replica region in current region.
// - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Identity.GetDomains(ctx, &identity.GetDomainsArgs{
//				CompartmentId:   _var.Compartment_id,
//				DisplayName:     pulumi.StringRef(_var.Domain_display_name),
//				HomeRegionUrl:   pulumi.StringRef(_var.Domain_home_region_url),
//				IsHiddenOnLogin: pulumi.BoolRef(_var.Domain_is_hidden_on_login),
//				LicenseType:     pulumi.StringRef(_var.Domain_license_type),
//				Name:            pulumi.StringRef(_var.Domain_name),
//				State:           pulumi.StringRef(_var.Domain_state),
//				Type:            pulumi.StringRef(_var.Domain_type),
//				Url:             pulumi.StringRef(_var.Domain_url),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDomains(ctx *pulumi.Context, args *GetDomainsArgs, opts ...pulumi.InvokeOption) (*GetDomainsResult, error) {
	var rv GetDomainsResult
	err := ctx.Invoke("oci:Identity/getDomains:getDomains", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDomains.
type GetDomainsArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string `pulumi:"compartmentId"`
	// The mutable display name of the domain
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetDomainsFilter `pulumi:"filters"`
	// The region specific domain URL
	HomeRegionUrl *string `pulumi:"homeRegionUrl"`
	// Indicate if the domain is visible at login screen or not
	IsHiddenOnLogin *bool `pulumi:"isHiddenOnLogin"`
	// The domain license type
	LicenseType *string `pulumi:"licenseType"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
	// The domain type
	Type *string `pulumi:"type"`
	// The region agnostic domain URL
	Url *string `pulumi:"url"`
}

// A collection of values returned by getDomains.
type GetDomainsResult struct {
	// The OCID of the compartment containing the domain.
	CompartmentId string `pulumi:"compartmentId"`
	// The mutable display name of the domain
	DisplayName *string `pulumi:"displayName"`
	// The list of domains.
	Domains []GetDomainsDomain `pulumi:"domains"`
	Filters []GetDomainsFilter `pulumi:"filters"`
	// Region specific domain URL.
	HomeRegionUrl *string `pulumi:"homeRegionUrl"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Indicates whether domain is hidden on login screen or not.
	IsHiddenOnLogin *bool `pulumi:"isHiddenOnLogin"`
	// The License type of Domain
	LicenseType *string `pulumi:"licenseType"`
	Name        *string `pulumi:"name"`
	// The current state.
	State *string `pulumi:"state"`
	// The type of the domain.
	Type *string `pulumi:"type"`
	// Region agnostic domain URL.
	Url *string `pulumi:"url"`
}

func GetDomainsOutput(ctx *pulumi.Context, args GetDomainsOutputArgs, opts ...pulumi.InvokeOption) GetDomainsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDomainsResult, error) {
			args := v.(GetDomainsArgs)
			r, err := GetDomains(ctx, &args, opts...)
			var s GetDomainsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDomainsResultOutput)
}

// A collection of arguments for invoking getDomains.
type GetDomainsOutputArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The mutable display name of the domain
	DisplayName pulumi.StringPtrInput      `pulumi:"displayName"`
	Filters     GetDomainsFilterArrayInput `pulumi:"filters"`
	// The region specific domain URL
	HomeRegionUrl pulumi.StringPtrInput `pulumi:"homeRegionUrl"`
	// Indicate if the domain is visible at login screen or not
	IsHiddenOnLogin pulumi.BoolPtrInput `pulumi:"isHiddenOnLogin"`
	// The domain license type
	LicenseType pulumi.StringPtrInput `pulumi:"licenseType"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The domain type
	Type pulumi.StringPtrInput `pulumi:"type"`
	// The region agnostic domain URL
	Url pulumi.StringPtrInput `pulumi:"url"`
}

func (GetDomainsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsArgs)(nil)).Elem()
}

// A collection of values returned by getDomains.
type GetDomainsResultOutput struct{ *pulumi.OutputState }

func (GetDomainsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDomainsResult)(nil)).Elem()
}

func (o GetDomainsResultOutput) ToGetDomainsResultOutput() GetDomainsResultOutput {
	return o
}

func (o GetDomainsResultOutput) ToGetDomainsResultOutputWithContext(ctx context.Context) GetDomainsResultOutput {
	return o
}

// The OCID of the compartment containing the domain.
func (o GetDomainsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The mutable display name of the domain
func (o GetDomainsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of domains.
func (o GetDomainsResultOutput) Domains() GetDomainsDomainArrayOutput {
	return o.ApplyT(func(v GetDomainsResult) []GetDomainsDomain { return v.Domains }).(GetDomainsDomainArrayOutput)
}

func (o GetDomainsResultOutput) Filters() GetDomainsFilterArrayOutput {
	return o.ApplyT(func(v GetDomainsResult) []GetDomainsFilter { return v.Filters }).(GetDomainsFilterArrayOutput)
}

// Region specific domain URL.
func (o GetDomainsResultOutput) HomeRegionUrl() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.HomeRegionUrl }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDomainsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDomainsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether domain is hidden on login screen or not.
func (o GetDomainsResultOutput) IsHiddenOnLogin() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *bool { return v.IsHiddenOnLogin }).(pulumi.BoolPtrOutput)
}

// The License type of Domain
func (o GetDomainsResultOutput) LicenseType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.LicenseType }).(pulumi.StringPtrOutput)
}

func (o GetDomainsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state.
func (o GetDomainsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The type of the domain.
func (o GetDomainsResultOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.Type }).(pulumi.StringPtrOutput)
}

// Region agnostic domain URL.
func (o GetDomainsResultOutput) Url() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDomainsResult) *string { return v.Url }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDomainsResultOutput{})
}