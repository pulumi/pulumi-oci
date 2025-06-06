// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package optimizer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Histories in Oracle Cloud Infrastructure Optimizer service.
//
// Lists changes to the recommendations based on user activity.
// For example, lists when recommendations have been implemented, dismissed, postponed, or reactivated.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/optimizer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := optimizer.GetHistories(ctx, &optimizer.GetHistoriesArgs{
//				CompartmentId:           compartmentId,
//				CompartmentIdInSubtree:  historyCompartmentIdInSubtree,
//				IncludeResourceMetadata: pulumi.BoolRef(historyIncludeResourceMetadata),
//				Name:                    pulumi.StringRef(historyName),
//				RecommendationId:        pulumi.StringRef(testRecommendation.Id),
//				RecommendationName:      pulumi.StringRef(testRecommendation.Name),
//				ResourceType:            pulumi.StringRef(historyResourceType),
//				State:                   pulumi.StringRef(historyState),
//				Status:                  pulumi.StringRef(historyStatus),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetHistories(ctx *pulumi.Context, args *GetHistoriesArgs, opts ...pulumi.InvokeOption) (*GetHistoriesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetHistoriesResult
	err := ctx.Invoke("oci:Optimizer/getHistories:getHistories", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getHistories.
type GetHistoriesArgs struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	//
	// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
	CompartmentIdInSubtree bool                 `pulumi:"compartmentIdInSubtree"`
	Filters                []GetHistoriesFilter `pulumi:"filters"`
	// Supplement additional resource information in extended metadata response.
	IncludeResourceMetadata *bool `pulumi:"includeResourceMetadata"`
	// Optional. A filter that returns results that match the name specified.
	Name *string `pulumi:"name"`
	// The unique OCID associated with the recommendation.
	RecommendationId *string `pulumi:"recommendationId"`
	// Optional. A filter that returns results that match the recommendation name specified.
	RecommendationName *string `pulumi:"recommendationName"`
	// Optional. A filter that returns results that match the resource type specified.
	ResourceType *string `pulumi:"resourceType"`
	// A filter that returns results that match the lifecycle state specified.
	State *string `pulumi:"state"`
	// A filter that returns recommendations that match the status specified.
	Status *string `pulumi:"status"`
}

// A collection of values returned by getHistories.
type GetHistoriesResult struct {
	// The OCID of the compartment.
	CompartmentId          string               `pulumi:"compartmentId"`
	CompartmentIdInSubtree bool                 `pulumi:"compartmentIdInSubtree"`
	Filters                []GetHistoriesFilter `pulumi:"filters"`
	// The list of history_collection.
	HistoryCollections []GetHistoriesHistoryCollection `pulumi:"historyCollections"`
	// The provider-assigned unique ID for this managed resource.
	Id                      string `pulumi:"id"`
	IncludeResourceMetadata *bool  `pulumi:"includeResourceMetadata"`
	// The name assigned to the resource.
	Name *string `pulumi:"name"`
	// The unique OCID associated with the recommendation.
	RecommendationId *string `pulumi:"recommendationId"`
	// The name assigned to the recommendation.
	RecommendationName *string `pulumi:"recommendationName"`
	// The kind of resource.
	ResourceType *string `pulumi:"resourceType"`
	// The recommendation history's current state.
	State *string `pulumi:"state"`
	// The current status of the resource action.
	Status *string `pulumi:"status"`
}

func GetHistoriesOutput(ctx *pulumi.Context, args GetHistoriesOutputArgs, opts ...pulumi.InvokeOption) GetHistoriesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetHistoriesResultOutput, error) {
			args := v.(GetHistoriesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Optimizer/getHistories:getHistories", args, GetHistoriesResultOutput{}, options).(GetHistoriesResultOutput), nil
		}).(GetHistoriesResultOutput)
}

// A collection of arguments for invoking getHistories.
type GetHistoriesOutputArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	//
	// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
	CompartmentIdInSubtree pulumi.BoolInput             `pulumi:"compartmentIdInSubtree"`
	Filters                GetHistoriesFilterArrayInput `pulumi:"filters"`
	// Supplement additional resource information in extended metadata response.
	IncludeResourceMetadata pulumi.BoolPtrInput `pulumi:"includeResourceMetadata"`
	// Optional. A filter that returns results that match the name specified.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The unique OCID associated with the recommendation.
	RecommendationId pulumi.StringPtrInput `pulumi:"recommendationId"`
	// Optional. A filter that returns results that match the recommendation name specified.
	RecommendationName pulumi.StringPtrInput `pulumi:"recommendationName"`
	// Optional. A filter that returns results that match the resource type specified.
	ResourceType pulumi.StringPtrInput `pulumi:"resourceType"`
	// A filter that returns results that match the lifecycle state specified.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter that returns recommendations that match the status specified.
	Status pulumi.StringPtrInput `pulumi:"status"`
}

func (GetHistoriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetHistoriesArgs)(nil)).Elem()
}

// A collection of values returned by getHistories.
type GetHistoriesResultOutput struct{ *pulumi.OutputState }

func (GetHistoriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetHistoriesResult)(nil)).Elem()
}

func (o GetHistoriesResultOutput) ToGetHistoriesResultOutput() GetHistoriesResultOutput {
	return o
}

func (o GetHistoriesResultOutput) ToGetHistoriesResultOutputWithContext(ctx context.Context) GetHistoriesResultOutput {
	return o
}

// The OCID of the compartment.
func (o GetHistoriesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetHistoriesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetHistoriesResultOutput) CompartmentIdInSubtree() pulumi.BoolOutput {
	return o.ApplyT(func(v GetHistoriesResult) bool { return v.CompartmentIdInSubtree }).(pulumi.BoolOutput)
}

func (o GetHistoriesResultOutput) Filters() GetHistoriesFilterArrayOutput {
	return o.ApplyT(func(v GetHistoriesResult) []GetHistoriesFilter { return v.Filters }).(GetHistoriesFilterArrayOutput)
}

// The list of history_collection.
func (o GetHistoriesResultOutput) HistoryCollections() GetHistoriesHistoryCollectionArrayOutput {
	return o.ApplyT(func(v GetHistoriesResult) []GetHistoriesHistoryCollection { return v.HistoryCollections }).(GetHistoriesHistoryCollectionArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetHistoriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetHistoriesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetHistoriesResultOutput) IncludeResourceMetadata() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *bool { return v.IncludeResourceMetadata }).(pulumi.BoolPtrOutput)
}

// The name assigned to the resource.
func (o GetHistoriesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The unique OCID associated with the recommendation.
func (o GetHistoriesResultOutput) RecommendationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.RecommendationId }).(pulumi.StringPtrOutput)
}

// The name assigned to the recommendation.
func (o GetHistoriesResultOutput) RecommendationName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.RecommendationName }).(pulumi.StringPtrOutput)
}

// The kind of resource.
func (o GetHistoriesResultOutput) ResourceType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.ResourceType }).(pulumi.StringPtrOutput)
}

// The recommendation history's current state.
func (o GetHistoriesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The current status of the resource action.
func (o GetHistoriesResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetHistoriesResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetHistoriesResultOutput{})
}
