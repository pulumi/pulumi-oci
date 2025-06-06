// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apm

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Apm Domains in Oracle Cloud Infrastructure Apm service.
//
// Lists all APM domains for the specified tenant compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/apm"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := apm.GetApmDomains(ctx, &apm.GetApmDomainsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(apmDomainDisplayName),
//				State:         pulumi.StringRef(apmDomainState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetApmDomains(ctx *pulumi.Context, args *GetApmDomainsArgs, opts ...pulumi.InvokeOption) (*GetApmDomainsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetApmDomainsResult
	err := ctx.Invoke("oci:Apm/getApmDomains:getApmDomains", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApmDomains.
type GetApmDomainsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string               `pulumi:"displayName"`
	Filters     []GetApmDomainsFilter `pulumi:"filters"`
	// A filter to return only resources that match the given life-cycle state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getApmDomains.
type GetApmDomainsResult struct {
	// The list of apm_domains.
	ApmDomains []GetApmDomainsApmDomain `pulumi:"apmDomains"`
	// The OCID of the compartment corresponding to the APM domain.
	CompartmentId string `pulumi:"compartmentId"`
	// Display name of the APM domain, which can be updated.
	DisplayName *string               `pulumi:"displayName"`
	Filters     []GetApmDomainsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the APM domain.
	State *string `pulumi:"state"`
}

func GetApmDomainsOutput(ctx *pulumi.Context, args GetApmDomainsOutputArgs, opts ...pulumi.InvokeOption) GetApmDomainsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetApmDomainsResultOutput, error) {
			args := v.(GetApmDomainsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Apm/getApmDomains:getApmDomains", args, GetApmDomainsResultOutput{}, options).(GetApmDomainsResultOutput), nil
		}).(GetApmDomainsResultOutput)
}

// A collection of arguments for invoking getApmDomains.
type GetApmDomainsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput         `pulumi:"displayName"`
	Filters     GetApmDomainsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given life-cycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetApmDomainsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApmDomainsArgs)(nil)).Elem()
}

// A collection of values returned by getApmDomains.
type GetApmDomainsResultOutput struct{ *pulumi.OutputState }

func (GetApmDomainsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApmDomainsResult)(nil)).Elem()
}

func (o GetApmDomainsResultOutput) ToGetApmDomainsResultOutput() GetApmDomainsResultOutput {
	return o
}

func (o GetApmDomainsResultOutput) ToGetApmDomainsResultOutputWithContext(ctx context.Context) GetApmDomainsResultOutput {
	return o
}

// The list of apm_domains.
func (o GetApmDomainsResultOutput) ApmDomains() GetApmDomainsApmDomainArrayOutput {
	return o.ApplyT(func(v GetApmDomainsResult) []GetApmDomainsApmDomain { return v.ApmDomains }).(GetApmDomainsApmDomainArrayOutput)
}

// The OCID of the compartment corresponding to the APM domain.
func (o GetApmDomainsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetApmDomainsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Display name of the APM domain, which can be updated.
func (o GetApmDomainsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApmDomainsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetApmDomainsResultOutput) Filters() GetApmDomainsFilterArrayOutput {
	return o.ApplyT(func(v GetApmDomainsResult) []GetApmDomainsFilter { return v.Filters }).(GetApmDomainsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetApmDomainsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetApmDomainsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current lifecycle state of the APM domain.
func (o GetApmDomainsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApmDomainsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetApmDomainsResultOutput{})
}
