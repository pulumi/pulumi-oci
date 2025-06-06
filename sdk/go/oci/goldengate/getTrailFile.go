// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Trail File resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Lists the TrailFiles for a deployment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/goldengate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := goldengate.GetTrailFile(ctx, &goldengate.GetTrailFileArgs{
//				DeploymentId: testDeployment.Id,
//				TrailFileId:  testTrailFileOciGoldenGateTrailFile.Id,
//				DisplayName:  pulumi.StringRef(trailFileDisplayName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetTrailFile(ctx *pulumi.Context, args *GetTrailFileArgs, opts ...pulumi.InvokeOption) (*GetTrailFileResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetTrailFileResult
	err := ctx.Invoke("oci:GoldenGate/getTrailFile:getTrailFile", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTrailFile.
type GetTrailFileArgs struct {
	// A unique Deployment identifier.
	DeploymentId string `pulumi:"deploymentId"`
	// A filter to return only the resources that match the entire 'displayName' given.
	DisplayName *string `pulumi:"displayName"`
	// A Trail File identifier
	TrailFileId string `pulumi:"trailFileId"`
}

// A collection of values returned by getTrailFile.
type GetTrailFileResult struct {
	DeploymentId string `pulumi:"deploymentId"`
	// An object's Display Name.
	DisplayName *string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// An array of TrailFiles.
	Items []GetTrailFileItem `pulumi:"items"`
	// The time the data was last fetched from the deployment. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeLastFetched string `pulumi:"timeLastFetched"`
	// The TrailFile Id.
	TrailFileId string `pulumi:"trailFileId"`
}

func GetTrailFileOutput(ctx *pulumi.Context, args GetTrailFileOutputArgs, opts ...pulumi.InvokeOption) GetTrailFileResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetTrailFileResultOutput, error) {
			args := v.(GetTrailFileArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GoldenGate/getTrailFile:getTrailFile", args, GetTrailFileResultOutput{}, options).(GetTrailFileResultOutput), nil
		}).(GetTrailFileResultOutput)
}

// A collection of arguments for invoking getTrailFile.
type GetTrailFileOutputArgs struct {
	// A unique Deployment identifier.
	DeploymentId pulumi.StringInput `pulumi:"deploymentId"`
	// A filter to return only the resources that match the entire 'displayName' given.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A Trail File identifier
	TrailFileId pulumi.StringInput `pulumi:"trailFileId"`
}

func (GetTrailFileOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTrailFileArgs)(nil)).Elem()
}

// A collection of values returned by getTrailFile.
type GetTrailFileResultOutput struct{ *pulumi.OutputState }

func (GetTrailFileResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTrailFileResult)(nil)).Elem()
}

func (o GetTrailFileResultOutput) ToGetTrailFileResultOutput() GetTrailFileResultOutput {
	return o
}

func (o GetTrailFileResultOutput) ToGetTrailFileResultOutputWithContext(ctx context.Context) GetTrailFileResultOutput {
	return o
}

func (o GetTrailFileResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTrailFileResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

// An object's Display Name.
func (o GetTrailFileResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTrailFileResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetTrailFileResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetTrailFileResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of TrailFiles.
func (o GetTrailFileResultOutput) Items() GetTrailFileItemArrayOutput {
	return o.ApplyT(func(v GetTrailFileResult) []GetTrailFileItem { return v.Items }).(GetTrailFileItemArrayOutput)
}

// The time the data was last fetched from the deployment. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o GetTrailFileResultOutput) TimeLastFetched() pulumi.StringOutput {
	return o.ApplyT(func(v GetTrailFileResult) string { return v.TimeLastFetched }).(pulumi.StringOutput)
}

// The TrailFile Id.
func (o GetTrailFileResultOutput) TrailFileId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTrailFileResult) string { return v.TrailFileId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetTrailFileResultOutput{})
}
