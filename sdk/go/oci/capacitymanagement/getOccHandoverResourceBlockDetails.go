// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Occ Handover Resource Block Details in Oracle Cloud Infrastructure Capacity Management service.
//
// List details about a given occHandoverResourceBlock.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.GetOccHandoverResourceBlockDetails(ctx, &capacitymanagement.GetOccHandoverResourceBlockDetailsArgs{
//				OccHandoverResourceBlockId: testOccHandoverResourceBlock.Id,
//				HostId:                     pulumi.StringRef(testHost.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOccHandoverResourceBlockDetails(ctx *pulumi.Context, args *GetOccHandoverResourceBlockDetailsArgs, opts ...pulumi.InvokeOption) (*GetOccHandoverResourceBlockDetailsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetOccHandoverResourceBlockDetailsResult
	err := ctx.Invoke("oci:CapacityManagement/getOccHandoverResourceBlockDetails:getOccHandoverResourceBlockDetails", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOccHandoverResourceBlockDetails.
type GetOccHandoverResourceBlockDetailsArgs struct {
	Filters []GetOccHandoverResourceBlockDetailsFilter `pulumi:"filters"`
	// This fiter is applicable only for COMPUTE namespace. It helps in fetching of all resource block details for which the hostId is equal to the one provided in this query param.
	HostId *string `pulumi:"hostId"`
	// The OCID of the OccHandoverResource which is a required query parameter for listing OccHandoverResourceDetails.
	OccHandoverResourceBlockId string `pulumi:"occHandoverResourceBlockId"`
}

// A collection of values returned by getOccHandoverResourceBlockDetails.
type GetOccHandoverResourceBlockDetailsResult struct {
	Filters []GetOccHandoverResourceBlockDetailsFilter `pulumi:"filters"`
	HostId  *string                                    `pulumi:"hostId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of occ_handover_resource_block_detail_collection.
	OccHandoverResourceBlockDetailCollections []GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection `pulumi:"occHandoverResourceBlockDetailCollections"`
	OccHandoverResourceBlockId                string                                                                       `pulumi:"occHandoverResourceBlockId"`
}

func GetOccHandoverResourceBlockDetailsOutput(ctx *pulumi.Context, args GetOccHandoverResourceBlockDetailsOutputArgs, opts ...pulumi.InvokeOption) GetOccHandoverResourceBlockDetailsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetOccHandoverResourceBlockDetailsResultOutput, error) {
			args := v.(GetOccHandoverResourceBlockDetailsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getOccHandoverResourceBlockDetails:getOccHandoverResourceBlockDetails", args, GetOccHandoverResourceBlockDetailsResultOutput{}, options).(GetOccHandoverResourceBlockDetailsResultOutput), nil
		}).(GetOccHandoverResourceBlockDetailsResultOutput)
}

// A collection of arguments for invoking getOccHandoverResourceBlockDetails.
type GetOccHandoverResourceBlockDetailsOutputArgs struct {
	Filters GetOccHandoverResourceBlockDetailsFilterArrayInput `pulumi:"filters"`
	// This fiter is applicable only for COMPUTE namespace. It helps in fetching of all resource block details for which the hostId is equal to the one provided in this query param.
	HostId pulumi.StringPtrInput `pulumi:"hostId"`
	// The OCID of the OccHandoverResource which is a required query parameter for listing OccHandoverResourceDetails.
	OccHandoverResourceBlockId pulumi.StringInput `pulumi:"occHandoverResourceBlockId"`
}

func (GetOccHandoverResourceBlockDetailsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccHandoverResourceBlockDetailsArgs)(nil)).Elem()
}

// A collection of values returned by getOccHandoverResourceBlockDetails.
type GetOccHandoverResourceBlockDetailsResultOutput struct{ *pulumi.OutputState }

func (GetOccHandoverResourceBlockDetailsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccHandoverResourceBlockDetailsResult)(nil)).Elem()
}

func (o GetOccHandoverResourceBlockDetailsResultOutput) ToGetOccHandoverResourceBlockDetailsResultOutput() GetOccHandoverResourceBlockDetailsResultOutput {
	return o
}

func (o GetOccHandoverResourceBlockDetailsResultOutput) ToGetOccHandoverResourceBlockDetailsResultOutputWithContext(ctx context.Context) GetOccHandoverResourceBlockDetailsResultOutput {
	return o
}

func (o GetOccHandoverResourceBlockDetailsResultOutput) Filters() GetOccHandoverResourceBlockDetailsFilterArrayOutput {
	return o.ApplyT(func(v GetOccHandoverResourceBlockDetailsResult) []GetOccHandoverResourceBlockDetailsFilter {
		return v.Filters
	}).(GetOccHandoverResourceBlockDetailsFilterArrayOutput)
}

func (o GetOccHandoverResourceBlockDetailsResultOutput) HostId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccHandoverResourceBlockDetailsResult) *string { return v.HostId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetOccHandoverResourceBlockDetailsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetOccHandoverResourceBlockDetailsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of occ_handover_resource_block_detail_collection.
func (o GetOccHandoverResourceBlockDetailsResultOutput) OccHandoverResourceBlockDetailCollections() GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionArrayOutput {
	return o.ApplyT(func(v GetOccHandoverResourceBlockDetailsResult) []GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection {
		return v.OccHandoverResourceBlockDetailCollections
	}).(GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionArrayOutput)
}

func (o GetOccHandoverResourceBlockDetailsResultOutput) OccHandoverResourceBlockId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOccHandoverResourceBlockDetailsResult) string { return v.OccHandoverResourceBlockId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOccHandoverResourceBlockDetailsResultOutput{})
}
