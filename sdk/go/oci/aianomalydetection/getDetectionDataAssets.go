// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package aianomalydetection

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Data Assets in Oracle Cloud Infrastructure Ai Anomaly Detection service.
//
// Returns a list of DataAssets.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/AiAnomalyDetection"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := AiAnomalyDetection.GetDetectionDataAssets(ctx, &aianomalydetection.GetDetectionDataAssetsArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Data_asset_display_name),
//				ProjectId:     pulumi.StringRef(oci_ai_anomaly_detection_project.Test_project.Id),
//				State:         pulumi.StringRef(_var.Data_asset_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDetectionDataAssets(ctx *pulumi.Context, args *GetDetectionDataAssetsArgs, opts ...pulumi.InvokeOption) (*GetDetectionDataAssetsResult, error) {
	var rv GetDetectionDataAssetsResult
	err := ctx.Invoke("oci:AiAnomalyDetection/getDetectionDataAssets:getDetectionDataAssets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDetectionDataAssets.
type GetDetectionDataAssetsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetDetectionDataAssetsFilter `pulumi:"filters"`
	// The ID of the project for which to list the objects.
	ProjectId *string `pulumi:"projectId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDetectionDataAssets.
type GetDetectionDataAssetsResult struct {
	// The OCID of the compartment containing the DataAsset.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of data_asset_collection.
	DataAssetCollections []GetDetectionDataAssetsDataAssetCollection `pulumi:"dataAssetCollections"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetDetectionDataAssetsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The Unique project id which is created at project creation that is immutable on creation.
	ProjectId *string `pulumi:"projectId"`
	// The lifecycle state of the Data Asset.
	State *string `pulumi:"state"`
}

func GetDetectionDataAssetsOutput(ctx *pulumi.Context, args GetDetectionDataAssetsOutputArgs, opts ...pulumi.InvokeOption) GetDetectionDataAssetsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDetectionDataAssetsResult, error) {
			args := v.(GetDetectionDataAssetsArgs)
			r, err := GetDetectionDataAssets(ctx, &args, opts...)
			var s GetDetectionDataAssetsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDetectionDataAssetsResultOutput)
}

// A collection of arguments for invoking getDetectionDataAssets.
type GetDetectionDataAssetsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                  `pulumi:"displayName"`
	Filters     GetDetectionDataAssetsFilterArrayInput `pulumi:"filters"`
	// The ID of the project for which to list the objects.
	ProjectId pulumi.StringPtrInput `pulumi:"projectId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDetectionDataAssetsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDetectionDataAssetsArgs)(nil)).Elem()
}

// A collection of values returned by getDetectionDataAssets.
type GetDetectionDataAssetsResultOutput struct{ *pulumi.OutputState }

func (GetDetectionDataAssetsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDetectionDataAssetsResult)(nil)).Elem()
}

func (o GetDetectionDataAssetsResultOutput) ToGetDetectionDataAssetsResultOutput() GetDetectionDataAssetsResultOutput {
	return o
}

func (o GetDetectionDataAssetsResultOutput) ToGetDetectionDataAssetsResultOutputWithContext(ctx context.Context) GetDetectionDataAssetsResultOutput {
	return o
}

// The OCID of the compartment containing the DataAsset.
func (o GetDetectionDataAssetsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of data_asset_collection.
func (o GetDetectionDataAssetsResultOutput) DataAssetCollections() GetDetectionDataAssetsDataAssetCollectionArrayOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) []GetDetectionDataAssetsDataAssetCollection {
		return v.DataAssetCollections
	}).(GetDetectionDataAssetsDataAssetCollectionArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetDetectionDataAssetsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDetectionDataAssetsResultOutput) Filters() GetDetectionDataAssetsFilterArrayOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) []GetDetectionDataAssetsFilter { return v.Filters }).(GetDetectionDataAssetsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDetectionDataAssetsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The Unique project id which is created at project creation that is immutable on creation.
func (o GetDetectionDataAssetsResultOutput) ProjectId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) *string { return v.ProjectId }).(pulumi.StringPtrOutput)
}

// The lifecycle state of the Data Asset.
func (o GetDetectionDataAssetsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDetectionDataAssetsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDetectionDataAssetsResultOutput{})
}