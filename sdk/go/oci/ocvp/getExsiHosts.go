// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ocvp

import (
	"context"
	"reflect"

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
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Ocvp"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Ocvp.GetExsiHosts(ctx, &ocvp.GetExsiHostsArgs{
//				ComputeInstanceId: pulumi.StringRef(oci_core_instance.Test_instance.Id),
//				DisplayName:       pulumi.StringRef(_var.Esxi_host_display_name),
//				SddcId:            pulumi.StringRef(oci_ocvp_sddc.Test_sddc.Id),
//				State:             pulumi.StringRef(_var.Esxi_host_state),
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
	var rv GetExsiHostsResult
	err := ctx.Invoke("oci:Ocvp/getExsiHosts:getExsiHosts", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExsiHosts.
type GetExsiHostsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute instance.
	ComputeInstanceId *string `pulumi:"computeInstanceId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string              `pulumi:"displayName"`
	Filters     []GetExsiHostsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
	SddcId *string `pulumi:"sddcId"`
	// The lifecycle state of the resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getExsiHosts.
type GetExsiHostsResult struct {
	// In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
	ComputeInstanceId *string `pulumi:"computeInstanceId"`
	// A descriptive name for the ESXi host. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The list of esxi_host_collection.
	EsxiHostCollections []GetExsiHostsEsxiHostCollection `pulumi:"esxiHostCollections"`
	Filters             []GetExsiHostsFilter             `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
	SddcId *string `pulumi:"sddcId"`
	// The current state of the ESXi host.
	State *string `pulumi:"state"`
}

func GetExsiHostsOutput(ctx *pulumi.Context, args GetExsiHostsOutputArgs, opts ...pulumi.InvokeOption) GetExsiHostsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetExsiHostsResult, error) {
			args := v.(GetExsiHostsArgs)
			r, err := GetExsiHosts(ctx, &args, opts...)
			var s GetExsiHostsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetExsiHostsResultOutput)
}

// A collection of arguments for invoking getExsiHosts.
type GetExsiHostsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute instance.
	ComputeInstanceId pulumi.StringPtrInput `pulumi:"computeInstanceId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput        `pulumi:"displayName"`
	Filters     GetExsiHostsFilterArrayInput `pulumi:"filters"`
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