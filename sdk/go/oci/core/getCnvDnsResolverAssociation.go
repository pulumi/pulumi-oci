// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vcn Dns Resolver Association resource in Oracle Cloud Infrastructure Core service.
//
// # Get the associated DNS resolver information with a vcn
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetCnvDnsResolverAssociation(ctx, &core.GetCnvDnsResolverAssociationArgs{
//				VcnId: testVcn.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCnvDnsResolverAssociation(ctx *pulumi.Context, args *GetCnvDnsResolverAssociationArgs, opts ...pulumi.InvokeOption) (*GetCnvDnsResolverAssociationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCnvDnsResolverAssociationResult
	err := ctx.Invoke("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCnvDnsResolverAssociation.
type GetCnvDnsResolverAssociationArgs struct {
	// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId string `pulumi:"vcnId"`
}

// A collection of values returned by getCnvDnsResolverAssociation.
type GetCnvDnsResolverAssociationResult struct {
	// The OCID of the DNS resolver in the association. We won't have the DNS resolver id as soon as vcn
	// is created, we will create it asynchronously. It would be null until it is actually created.
	DnsResolverId string `pulumi:"dnsResolverId"`
	// The provider-assigned unique ID for this managed resource.
	Id    string `pulumi:"id"`
	State string `pulumi:"state"`
	// The OCID of the VCN in the association.
	VcnId string `pulumi:"vcnId"`
}

func GetCnvDnsResolverAssociationOutput(ctx *pulumi.Context, args GetCnvDnsResolverAssociationOutputArgs, opts ...pulumi.InvokeOption) GetCnvDnsResolverAssociationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCnvDnsResolverAssociationResultOutput, error) {
			args := v.(GetCnvDnsResolverAssociationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getCnvDnsResolverAssociation:getCnvDnsResolverAssociation", args, GetCnvDnsResolverAssociationResultOutput{}, options).(GetCnvDnsResolverAssociationResultOutput), nil
		}).(GetCnvDnsResolverAssociationResultOutput)
}

// A collection of arguments for invoking getCnvDnsResolverAssociation.
type GetCnvDnsResolverAssociationOutputArgs struct {
	// Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringInput `pulumi:"vcnId"`
}

func (GetCnvDnsResolverAssociationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCnvDnsResolverAssociationArgs)(nil)).Elem()
}

// A collection of values returned by getCnvDnsResolverAssociation.
type GetCnvDnsResolverAssociationResultOutput struct{ *pulumi.OutputState }

func (GetCnvDnsResolverAssociationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCnvDnsResolverAssociationResult)(nil)).Elem()
}

func (o GetCnvDnsResolverAssociationResultOutput) ToGetCnvDnsResolverAssociationResultOutput() GetCnvDnsResolverAssociationResultOutput {
	return o
}

func (o GetCnvDnsResolverAssociationResultOutput) ToGetCnvDnsResolverAssociationResultOutputWithContext(ctx context.Context) GetCnvDnsResolverAssociationResultOutput {
	return o
}

// The OCID of the DNS resolver in the association. We won't have the DNS resolver id as soon as vcn
// is created, we will create it asynchronously. It would be null until it is actually created.
func (o GetCnvDnsResolverAssociationResultOutput) DnsResolverId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCnvDnsResolverAssociationResult) string { return v.DnsResolverId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCnvDnsResolverAssociationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCnvDnsResolverAssociationResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetCnvDnsResolverAssociationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetCnvDnsResolverAssociationResult) string { return v.State }).(pulumi.StringOutput)
}

// The OCID of the VCN in the association.
func (o GetCnvDnsResolverAssociationResultOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCnvDnsResolverAssociationResult) string { return v.VcnId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCnvDnsResolverAssociationResultOutput{})
}
