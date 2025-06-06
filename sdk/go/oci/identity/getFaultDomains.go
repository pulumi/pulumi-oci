// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fault Domains in Oracle Cloud Infrastructure Identity service.
//
// Lists the Fault Domains in your tenancy. Specify the OCID of either the tenancy or another
// of your compartments as the value for the compartment ID (remember that the tenancy is simply the root compartment).
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
//			_, err := identity.GetFaultDomains(ctx, &identity.GetFaultDomainsArgs{
//				AvailabilityDomain: faultDomainAvailabilityDomain,
//				CompartmentId:      compartmentId,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFaultDomains(ctx *pulumi.Context, args *GetFaultDomainsArgs, opts ...pulumi.InvokeOption) (*GetFaultDomainsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFaultDomainsResult
	err := ctx.Invoke("oci:Identity/getFaultDomains:getFaultDomains", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFaultDomains.
type GetFaultDomainsArgs struct {
	// The name of the availibilityDomain.
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                  `pulumi:"compartmentId"`
	Filters       []GetFaultDomainsFilter `pulumi:"filters"`
}

// A collection of values returned by getFaultDomains.
type GetFaultDomainsResult struct {
	// The name of the availabilityDomain where the Fault Domain belongs.
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The OCID of the compartment. Currently only tenancy (root) compartment can be provided.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of fault_domains.
	FaultDomains []GetFaultDomainsFaultDomain `pulumi:"faultDomains"`
	Filters      []GetFaultDomainsFilter      `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetFaultDomainsOutput(ctx *pulumi.Context, args GetFaultDomainsOutputArgs, opts ...pulumi.InvokeOption) GetFaultDomainsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFaultDomainsResultOutput, error) {
			args := v.(GetFaultDomainsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getFaultDomains:getFaultDomains", args, GetFaultDomainsResultOutput{}, options).(GetFaultDomainsResultOutput), nil
		}).(GetFaultDomainsResultOutput)
}

// A collection of arguments for invoking getFaultDomains.
type GetFaultDomainsOutputArgs struct {
	// The name of the availibilityDomain.
	AvailabilityDomain pulumi.StringInput `pulumi:"availabilityDomain"`
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput              `pulumi:"compartmentId"`
	Filters       GetFaultDomainsFilterArrayInput `pulumi:"filters"`
}

func (GetFaultDomainsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFaultDomainsArgs)(nil)).Elem()
}

// A collection of values returned by getFaultDomains.
type GetFaultDomainsResultOutput struct{ *pulumi.OutputState }

func (GetFaultDomainsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFaultDomainsResult)(nil)).Elem()
}

func (o GetFaultDomainsResultOutput) ToGetFaultDomainsResultOutput() GetFaultDomainsResultOutput {
	return o
}

func (o GetFaultDomainsResultOutput) ToGetFaultDomainsResultOutputWithContext(ctx context.Context) GetFaultDomainsResultOutput {
	return o
}

// The name of the availabilityDomain where the Fault Domain belongs.
func (o GetFaultDomainsResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v GetFaultDomainsResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The OCID of the compartment. Currently only tenancy (root) compartment can be provided.
func (o GetFaultDomainsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFaultDomainsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of fault_domains.
func (o GetFaultDomainsResultOutput) FaultDomains() GetFaultDomainsFaultDomainArrayOutput {
	return o.ApplyT(func(v GetFaultDomainsResult) []GetFaultDomainsFaultDomain { return v.FaultDomains }).(GetFaultDomainsFaultDomainArrayOutput)
}

func (o GetFaultDomainsResultOutput) Filters() GetFaultDomainsFilterArrayOutput {
	return o.ApplyT(func(v GetFaultDomainsResult) []GetFaultDomainsFilter { return v.Filters }).(GetFaultDomainsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFaultDomainsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFaultDomainsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFaultDomainsResultOutput{})
}
