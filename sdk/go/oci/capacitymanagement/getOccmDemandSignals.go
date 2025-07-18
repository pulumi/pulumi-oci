// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Occm Demand Signals in Oracle Cloud Infrastructure Capacity Management service.
//
// This GET call is used to list all demand signals within the compartment passed as a query parameter.
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
//			_, err := capacitymanagement.GetOccmDemandSignals(ctx, &capacitymanagement.GetOccmDemandSignalsArgs{
//				CompartmentId:    compartmentId,
//				DisplayName:      pulumi.StringRef(occmDemandSignalDisplayName),
//				Id:               pulumi.StringRef(occmDemandSignalId),
//				LifecycleDetails: pulumi.StringRef(occmDemandSignalLifecycleDetails),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetOccmDemandSignals(ctx *pulumi.Context, args *GetOccmDemandSignalsArgs, opts ...pulumi.InvokeOption) (*GetOccmDemandSignalsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetOccmDemandSignalsResult
	err := ctx.Invoke("oci:CapacityManagement/getOccmDemandSignals:getOccmDemandSignals", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOccmDemandSignals.
type GetOccmDemandSignalsArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetOccmDemandSignalsFilter `pulumi:"filters"`
	// A query parameter to filter the list of demand signals based on it's OCID.
	Id *string `pulumi:"id"`
	// A query parameter to filter the list of demand signals based on its state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
}

// A collection of values returned by getOccmDemandSignals.
type GetOccmDemandSignalsResult struct {
	// The OCID of the tenancy from which the request to create the demand signal was made.
	CompartmentId string `pulumi:"compartmentId"`
	// The display name of the demand signal.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetOccmDemandSignalsFilter `pulumi:"filters"`
	// The OCID of the demand signal.
	Id *string `pulumi:"id"`
	// The different states associated with a demand signal.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The list of occm_demand_signal_collection.
	OccmDemandSignalCollections []GetOccmDemandSignalsOccmDemandSignalCollection `pulumi:"occmDemandSignalCollections"`
}

func GetOccmDemandSignalsOutput(ctx *pulumi.Context, args GetOccmDemandSignalsOutputArgs, opts ...pulumi.InvokeOption) GetOccmDemandSignalsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetOccmDemandSignalsResultOutput, error) {
			args := v.(GetOccmDemandSignalsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getOccmDemandSignals:getOccmDemandSignals", args, GetOccmDemandSignalsResultOutput{}, options).(GetOccmDemandSignalsResultOutput), nil
		}).(GetOccmDemandSignalsResultOutput)
}

// A collection of arguments for invoking getOccmDemandSignals.
type GetOccmDemandSignalsOutputArgs struct {
	// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only the resources that match the entire display name. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                `pulumi:"displayName"`
	Filters     GetOccmDemandSignalsFilterArrayInput `pulumi:"filters"`
	// A query parameter to filter the list of demand signals based on it's OCID.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A query parameter to filter the list of demand signals based on its state.
	LifecycleDetails pulumi.StringPtrInput `pulumi:"lifecycleDetails"`
}

func (GetOccmDemandSignalsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccmDemandSignalsArgs)(nil)).Elem()
}

// A collection of values returned by getOccmDemandSignals.
type GetOccmDemandSignalsResultOutput struct{ *pulumi.OutputState }

func (GetOccmDemandSignalsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetOccmDemandSignalsResult)(nil)).Elem()
}

func (o GetOccmDemandSignalsResultOutput) ToGetOccmDemandSignalsResultOutput() GetOccmDemandSignalsResultOutput {
	return o
}

func (o GetOccmDemandSignalsResultOutput) ToGetOccmDemandSignalsResultOutputWithContext(ctx context.Context) GetOccmDemandSignalsResultOutput {
	return o
}

// The OCID of the tenancy from which the request to create the demand signal was made.
func (o GetOccmDemandSignalsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The display name of the demand signal.
func (o GetOccmDemandSignalsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetOccmDemandSignalsResultOutput) Filters() GetOccmDemandSignalsFilterArrayOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) []GetOccmDemandSignalsFilter { return v.Filters }).(GetOccmDemandSignalsFilterArrayOutput)
}

// The OCID of the demand signal.
func (o GetOccmDemandSignalsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The different states associated with a demand signal.
func (o GetOccmDemandSignalsResultOutput) LifecycleDetails() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) *string { return v.LifecycleDetails }).(pulumi.StringPtrOutput)
}

// The list of occm_demand_signal_collection.
func (o GetOccmDemandSignalsResultOutput) OccmDemandSignalCollections() GetOccmDemandSignalsOccmDemandSignalCollectionArrayOutput {
	return o.ApplyT(func(v GetOccmDemandSignalsResult) []GetOccmDemandSignalsOccmDemandSignalCollection {
		return v.OccmDemandSignalCollections
	}).(GetOccmDemandSignalsOccmDemandSignalCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetOccmDemandSignalsResultOutput{})
}
