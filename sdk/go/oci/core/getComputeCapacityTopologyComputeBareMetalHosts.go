// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Capacity Topology Compute Bare Metal Hosts in Oracle Cloud Infrastructure Core service.
//
// Lists compute bare metal hosts in the specified compute capacity topology.
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
//			_, err := core.GetComputeCapacityTopologyComputeBareMetalHosts(ctx, &core.GetComputeCapacityTopologyComputeBareMetalHostsArgs{
//				ComputeCapacityTopologyId: testComputeCapacityTopology.Id,
//				AvailabilityDomain:        pulumi.StringRef(computeCapacityTopologyComputeBareMetalHostAvailabilityDomain),
//				CompartmentId:             pulumi.StringRef(compartmentId),
//				ComputeHpcIslandId:        pulumi.StringRef(testComputeHpcIsland.Id),
//				ComputeLocalBlockId:       pulumi.StringRef(testComputeLocalBlock.Id),
//				ComputeNetworkBlockId:     pulumi.StringRef(testComputeNetworkBlock.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetComputeCapacityTopologyComputeBareMetalHosts(ctx *pulumi.Context, args *GetComputeCapacityTopologyComputeBareMetalHostsArgs, opts ...pulumi.InvokeOption) (*GetComputeCapacityTopologyComputeBareMetalHostsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetComputeCapacityTopologyComputeBareMetalHostsResult
	err := ctx.Invoke("oci:Core/getComputeCapacityTopologyComputeBareMetalHosts:getComputeCapacityTopologyComputeBareMetalHosts", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getComputeCapacityTopologyComputeBareMetalHosts.
type GetComputeCapacityTopologyComputeBareMetalHostsArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity topology.
	ComputeCapacityTopologyId string `pulumi:"computeCapacityTopologyId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
	ComputeHpcIslandId *string `pulumi:"computeHpcIslandId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute local block.
	ComputeLocalBlockId *string `pulumi:"computeLocalBlockId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
	ComputeNetworkBlockId *string                                                 `pulumi:"computeNetworkBlockId"`
	Filters               []GetComputeCapacityTopologyComputeBareMetalHostsFilter `pulumi:"filters"`
}

// A collection of values returned by getComputeCapacityTopologyComputeBareMetalHosts.
type GetComputeCapacityTopologyComputeBareMetalHostsResult struct {
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	CompartmentId      *string `pulumi:"compartmentId"`
	// The list of compute_bare_metal_host_collection.
	ComputeBareMetalHostCollections []GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection `pulumi:"computeBareMetalHostCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity topology.
	ComputeCapacityTopologyId string `pulumi:"computeCapacityTopologyId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
	ComputeHpcIslandId *string `pulumi:"computeHpcIslandId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
	ComputeLocalBlockId *string `pulumi:"computeLocalBlockId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute local block.
	ComputeNetworkBlockId *string                                                 `pulumi:"computeNetworkBlockId"`
	Filters               []GetComputeCapacityTopologyComputeBareMetalHostsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetComputeCapacityTopologyComputeBareMetalHostsOutput(ctx *pulumi.Context, args GetComputeCapacityTopologyComputeBareMetalHostsOutputArgs, opts ...pulumi.InvokeOption) GetComputeCapacityTopologyComputeBareMetalHostsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetComputeCapacityTopologyComputeBareMetalHostsResultOutput, error) {
			args := v.(GetComputeCapacityTopologyComputeBareMetalHostsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getComputeCapacityTopologyComputeBareMetalHosts:getComputeCapacityTopologyComputeBareMetalHosts", args, GetComputeCapacityTopologyComputeBareMetalHostsResultOutput{}, options).(GetComputeCapacityTopologyComputeBareMetalHostsResultOutput), nil
		}).(GetComputeCapacityTopologyComputeBareMetalHostsResultOutput)
}

// A collection of arguments for invoking getComputeCapacityTopologyComputeBareMetalHosts.
type GetComputeCapacityTopologyComputeBareMetalHostsOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity topology.
	ComputeCapacityTopologyId pulumi.StringInput `pulumi:"computeCapacityTopologyId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
	ComputeHpcIslandId pulumi.StringPtrInput `pulumi:"computeHpcIslandId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute local block.
	ComputeLocalBlockId pulumi.StringPtrInput `pulumi:"computeLocalBlockId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
	ComputeNetworkBlockId pulumi.StringPtrInput                                           `pulumi:"computeNetworkBlockId"`
	Filters               GetComputeCapacityTopologyComputeBareMetalHostsFilterArrayInput `pulumi:"filters"`
}

func (GetComputeCapacityTopologyComputeBareMetalHostsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeCapacityTopologyComputeBareMetalHostsArgs)(nil)).Elem()
}

// A collection of values returned by getComputeCapacityTopologyComputeBareMetalHosts.
type GetComputeCapacityTopologyComputeBareMetalHostsResultOutput struct{ *pulumi.OutputState }

func (GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeCapacityTopologyComputeBareMetalHostsResult)(nil)).Elem()
}

func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ToGetComputeCapacityTopologyComputeBareMetalHostsResultOutput() GetComputeCapacityTopologyComputeBareMetalHostsResultOutput {
	return o
}

func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ToGetComputeCapacityTopologyComputeBareMetalHostsResultOutputWithContext(ctx context.Context) GetComputeCapacityTopologyComputeBareMetalHostsResultOutput {
	return o
}

func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The list of compute_bare_metal_host_collection.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ComputeBareMetalHostCollections() GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionArrayOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) []GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection {
		return v.ComputeBareMetalHostCollections
	}).(GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity topology.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ComputeCapacityTopologyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) string {
		return v.ComputeCapacityTopologyId
	}).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute HPC island.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ComputeHpcIslandId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) *string { return v.ComputeHpcIslandId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute network block.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ComputeLocalBlockId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) *string { return v.ComputeLocalBlockId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute local block.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) ComputeNetworkBlockId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) *string { return v.ComputeNetworkBlockId }).(pulumi.StringPtrOutput)
}

func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) Filters() GetComputeCapacityTopologyComputeBareMetalHostsFilterArrayOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) []GetComputeCapacityTopologyComputeBareMetalHostsFilter {
		return v.Filters
	}).(GetComputeCapacityTopologyComputeBareMetalHostsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetComputeCapacityTopologyComputeBareMetalHostsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeCapacityTopologyComputeBareMetalHostsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetComputeCapacityTopologyComputeBareMetalHostsResultOutput{})
}
