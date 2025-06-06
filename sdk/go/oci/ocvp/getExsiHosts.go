// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ocvp

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Esxi Hosts in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
//
// Lists the ESXi hosts in the specified SDDC. The list can be filtered
// by Compute instance OCID or ESXi display name.
//
// Remember that in terms of implementation, an ESXi host is a Compute instance that
// is configured with the chosen bundle of VMware software. Each `EsxiHost`
// object has its own OCID (`id`), and a separate attribute for the OCID of
// the Compute instance (`computeInstanceId`). When filtering the list of
// ESXi hosts, you can specify the OCID of the Compute instance, not the
// ESXi host OCID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/ocvp"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ocvp.GetExsiHosts(ctx, &ocvp.GetExsiHostsArgs{
//				ClusterId:           pulumi.StringRef(testCluster.Id),
//				CompartmentId:       pulumi.StringRef(compartmentId),
//				ComputeInstanceId:   pulumi.StringRef(testInstance.Id),
//				DisplayName:         pulumi.StringRef(esxiHostDisplayName),
//				IsBillingDonorsOnly: pulumi.BoolRef(esxiHostIsBillingDonorsOnly),
//				IsSwapBillingOnly:   pulumi.BoolRef(esxiHostIsSwapBillingOnly),
//				SddcId:              pulumi.StringRef(testSddc.Id),
//				State:               pulumi.StringRef(esxiHostState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetExsiHosts(ctx *pulumi.Context, args *GetExsiHostsArgs, opts ...pulumi.InvokeOption) (*GetExsiHostsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetExsiHostsResult
	err := ctx.Invoke("oci:Ocvp/getExsiHosts:getExsiHosts", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExsiHosts.
type GetExsiHostsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC Cluster.
	ClusterId *string `pulumi:"clusterId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment as optional parameter.
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute instance.
	ComputeInstanceId *string `pulumi:"computeInstanceId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string              `pulumi:"displayName"`
	Filters     []GetExsiHostsFilter `pulumi:"filters"`
	// If this flag/param is set to True, we return only deleted hosts with LeftOver billingCycle.
	IsBillingDonorsOnly *bool `pulumi:"isBillingDonorsOnly"`
	// If this flag/param is set to True, we return only active hosts.
	IsSwapBillingOnly *bool `pulumi:"isSwapBillingOnly"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
	SddcId *string `pulumi:"sddcId"`
	// The lifecycle state of the resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getExsiHosts.
type GetExsiHostsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster that the ESXi host belongs to.
	ClusterId *string `pulumi:"clusterId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Cluster.
	CompartmentId *string `pulumi:"compartmentId"`
	// In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
	ComputeInstanceId *string `pulumi:"computeInstanceId"`
	// A descriptive name for the ESXi host. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The list of esxi_host_collection.
	EsxiHostCollections []GetExsiHostsEsxiHostCollection `pulumi:"esxiHostCollections"`
	Filters             []GetExsiHostsFilter             `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                  string `pulumi:"id"`
	IsBillingDonorsOnly *bool  `pulumi:"isBillingDonorsOnly"`
	IsSwapBillingOnly   *bool  `pulumi:"isSwapBillingOnly"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
	SddcId *string `pulumi:"sddcId"`
	// The current state of the ESXi host.
	State *string `pulumi:"state"`
}

func GetExsiHostsOutput(ctx *pulumi.Context, args GetExsiHostsOutputArgs, opts ...pulumi.InvokeOption) GetExsiHostsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetExsiHostsResultOutput, error) {
			args := v.(GetExsiHostsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Ocvp/getExsiHosts:getExsiHosts", args, GetExsiHostsResultOutput{}, options).(GetExsiHostsResultOutput), nil
		}).(GetExsiHostsResultOutput)
}

// A collection of arguments for invoking getExsiHosts.
type GetExsiHostsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC Cluster.
	ClusterId pulumi.StringPtrInput `pulumi:"clusterId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment as optional parameter.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute instance.
	ComputeInstanceId pulumi.StringPtrInput `pulumi:"computeInstanceId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput        `pulumi:"displayName"`
	Filters     GetExsiHostsFilterArrayInput `pulumi:"filters"`
	// If this flag/param is set to True, we return only deleted hosts with LeftOver billingCycle.
	IsBillingDonorsOnly pulumi.BoolPtrInput `pulumi:"isBillingDonorsOnly"`
	// If this flag/param is set to True, we return only active hosts.
	IsSwapBillingOnly pulumi.BoolPtrInput `pulumi:"isSwapBillingOnly"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
	SddcId pulumi.StringPtrInput `pulumi:"sddcId"`
	// The lifecycle state of the resource.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetExsiHostsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExsiHostsArgs)(nil)).Elem()
}

// A collection of values returned by getExsiHosts.
type GetExsiHostsResultOutput struct{ *pulumi.OutputState }

func (GetExsiHostsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExsiHostsResult)(nil)).Elem()
}

func (o GetExsiHostsResultOutput) ToGetExsiHostsResultOutput() GetExsiHostsResultOutput {
	return o
}

func (o GetExsiHostsResultOutput) ToGetExsiHostsResultOutputWithContext(ctx context.Context) GetExsiHostsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster that the ESXi host belongs to.
func (o GetExsiHostsResultOutput) ClusterId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.ClusterId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Cluster.
func (o GetExsiHostsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
func (o GetExsiHostsResultOutput) ComputeInstanceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.ComputeInstanceId }).(pulumi.StringPtrOutput)
}

// A descriptive name for the ESXi host. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetExsiHostsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of esxi_host_collection.
func (o GetExsiHostsResultOutput) EsxiHostCollections() GetExsiHostsEsxiHostCollectionArrayOutput {
	return o.ApplyT(func(v GetExsiHostsResult) []GetExsiHostsEsxiHostCollection { return v.EsxiHostCollections }).(GetExsiHostsEsxiHostCollectionArrayOutput)
}

func (o GetExsiHostsResultOutput) Filters() GetExsiHostsFilterArrayOutput {
	return o.ApplyT(func(v GetExsiHostsResult) []GetExsiHostsFilter { return v.Filters }).(GetExsiHostsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetExsiHostsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetExsiHostsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetExsiHostsResultOutput) IsBillingDonorsOnly() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *bool { return v.IsBillingDonorsOnly }).(pulumi.BoolPtrOutput)
}

func (o GetExsiHostsResultOutput) IsSwapBillingOnly() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *bool { return v.IsSwapBillingOnly }).(pulumi.BoolPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
func (o GetExsiHostsResultOutput) SddcId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.SddcId }).(pulumi.StringPtrOutput)
}

// The current state of the ESXi host.
func (o GetExsiHostsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExsiHostsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetExsiHostsResultOutput{})
}
